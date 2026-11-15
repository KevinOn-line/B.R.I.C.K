const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("brickDesktop", {
  getReceiverInfo: () => ipcRenderer.invoke("brick:receiver-info"),
  onReport: (callback) => {
    const listener = (_event, report) => callback(report);
    ipcRenderer.on("brick:report-received", listener);
    return () => ipcRenderer.removeListener("brick:report-received", listener);
  },
});
