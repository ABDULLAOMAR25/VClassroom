const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { ExpressPeerServer } = require("peer");
const { v4: uuidV4 } = require("uuid");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const peerServer = ExpressPeerServer(server, {
  debug: true,
});

app.use("/peerjs", peerServer);
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.redirect(`/${uuidV4()}`);
});

app.get("/:room", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

io.on("connection", (socket) => {
  socket.on("join-room", (roomId, userId) => {
    socket.join(roomId);
    socket.to(roomId).emit("user-connected", userId);

    socket.on("disconnect", () => {
      socket.to(roomId).emit("user-disconnected", userId);
    });
  });
});

server.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});