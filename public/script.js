const socket = io('/');
const videoGrid = document.getElementById('video-grid');
const myVideo = document.createElement('video');
myVideo.muted = true;

const myPeer = new Peer(undefined, {
  path: '/peerjs',
  host: '/',
  port: '3000'
});

let myStream;
const peers = {};

navigator.mediaDevices.getUserMedia({
  video: true,
  audio: true
}).then(stream => {
  myStream = stream;
  addVideoStream(myVideo, stream);

  myPeer.on('call', call => {
    call.answer(stream);
    const video = document.createElement('video');
    call.on('stream', userVideoStream => {
      addVideoStream(video, userVideoStream);
    });
    call.on('close', () => {
      video.remove();
    });
    peers[call.peer] = call;
  });

  socket.on('user-connected', userId => {
    connectToNewUser(userId, stream);
  });
});

socket.on('user-disconnected', userId => {
  if (peers[userId]) peers[userId].close();
});

myPeer.on('open', id => {
  const roomId = window.location.pathname.slice(1);
  socket.emit('join-room', roomId, id);
});

function connectToNewUser(userId, stream) {
  const call = myPeer.call(userId, stream);
  const video = document.createElement('video');
  call.on('stream', userVideoStream => {
    addVideoStream(video, userVideoStream);
  });
  call.on('close', () => {
    video.remove();
  });
  peers[userId] = call;
}

function addVideoStream(video, stream) {
  if (video.srcObject) return;
  video.srcObject = stream;
  video.addEventListener('loadedmetadata', () => video.play());
  videoGrid.append(video);
}