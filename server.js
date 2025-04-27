const express = require("express");
const chokidar = require("chokidar");
const socketIo = require("socket.io");
const cors = require("cors");
const fs = require("fs").promises;  // Use promises version by default
const fsSync = require("fs");  // Keep sync version for exists checks
const path = require("path");

const app = express();
const port = 5000;

// Enable CORS
app.use(cors());
app.use(express.static("public"));

// Create an HTTP server
const server = app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Set up Socket.io with CORS configuration
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:5173", // Vite's default development port
    methods: ["GET", "POST"],
    credentials: true
  },
});

// Define base paths
const basePath = __dirname;
const folderPath = path.join(basePath, "watched-folder");
const quarantineDir = path.join(basePath, 'quarantine');

// Create directories with proper permissions if they don't exist
try {
  if (!fsSync.existsSync(quarantineDir)) {
    fsSync.mkdirSync(quarantineDir, { recursive: true });
    console.log(`Created quarantine directory at: ${quarantineDir}`);
  }

  if (!fsSync.existsSync(folderPath)) {
    fsSync.mkdirSync(folderPath, { recursive: true });
    console.log(`Created watched folder at: ${folderPath}`);
  }
} catch (error) {
  console.error('Error creating directories:', error);
}

// Helper function to safely move file
async function safeQuarantineFile(sourcePath, fileName) {
  const timestamp = Date.now();
  const quarantineFileName = `quarantined_${timestamp}_${fileName}`;
  const quarantinePath = path.join(quarantineDir, quarantineFileName);

  try {
    // Read the source file
    const fileContent = await fs.readFile(sourcePath);
    
    // Write to quarantine location
    await fs.writeFile(quarantinePath, fileContent);
    
    // Verify the file was written correctly
    const sourceStats = await fs.stat(sourcePath);
    const quarantineStats = await fs.stat(quarantinePath);
    
    if (sourceStats.size === quarantineStats.size) {
      // If sizes match, delete the original
      await fs.unlink(sourcePath);
      return quarantinePath;
    } else {
      // If sizes don't match, delete the quarantine copy and throw error
      await fs.unlink(quarantinePath);
      throw new Error("File verification failed");
    }
  } catch (error) {
    // If anything goes wrong, attempt to clean up
    if (fsSync.existsSync(quarantinePath)) {
      await fs.unlink(quarantinePath).catch(console.error);
    }
    throw error;
  }
}

// Log when clients connect/disconnect
io.on("connection", (socket) => {
  console.log("Client connected");
  
  // Handle quarantine requests
  socket.on("quarantine-file", async (filePath) => {
    try {
      // Extract the filename from the alert message
      const fileNameMatch = filePath.match(/Malware file detected: (.+)$/);
      if (!fileNameMatch) {
        throw new Error("Invalid file path format");
      }
      const fileName = fileNameMatch[1];
      
      // Construct source path
      const fullPath = path.join(folderPath, fileName);
      
      console.log(`Attempting to quarantine file: ${fullPath}`);

      // Check if source file exists
      if (!fsSync.existsSync(fullPath)) {
        throw new Error(`File not found at: ${fullPath}`);
      }

      // Use safe quarantine function
      const quarantinePath = await safeQuarantineFile(fullPath, fileName);

      console.log(`Successfully moved file to quarantine: ${quarantinePath}`);
      socket.emit("log", `Successfully quarantined malicious file: ${fileName}`);
      
      // List files in quarantine directory
      const quarantinedFiles = await fs.readdir(quarantineDir);
      console.log('Files in quarantine:', quarantinedFiles);
      
    } catch (error) {
      console.error("Error during quarantine:", error);
      socket.emit("log", `Error quarantining file: ${error.message}`);
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

// Watch the folder for file changes
const watcher = chokidar.watch(folderPath, {
  ignored: /^\./,
  persistent: true,
});

watcher.on("add", (filePath) => {
  console.log(`File added: ${filePath}`);

  const fileName = path.basename(filePath);
  if (fileName.includes("malware")) {
    console.log(`Emitting malware-alert: Malware file detected: ${fileName}`);
    io.emit("malware-alert", `Malware file detected: ${fileName}`);
  } else {
    console.log(`Emitting log: File is safe: ${fileName}`);
    io.emit("log", `File is safe: ${fileName}`);
  }
});