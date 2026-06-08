import { WebSocketServer, WebSocket } from "ws";
import { handleChallengeResponse } from "../services/connectivityTestService";

export const machineToSocket = new Map<string, WebSocket>();

const wss = new WebSocketServer({
    port: 8080,
});

console.log("================================");
console.log("WebSocket server started on port 8080");
console.log("================================");

wss.on("connection", (ws, req) => {
    console.log("CLIENT CONNECTED COUNT:", wss.clients.size);
    console.log("================================");
    console.log("AGENT CONNECTED");
    console.log("IP:", req.socket.remoteAddress);
    console.log("================================");

    ws.on("message", async (raw) => {
        console.log("RAW MESSAGE RECEIVED FROM CLIENT");
        console.log("================================");
        console.log("RAW MESSAGE:", raw.toString());
        console.log("================================");

        try {
            let msg;

            try {
                msg = JSON.parse(raw.toString());
            } catch (err) {
                console.log(
                    "Ignoring non-JSON WS message:",
                    raw.toString()
                );
                return;
            }

            console.log("================================");
            console.log("MESSAGE FROM AGENT");
            console.log(msg);
            console.log("================================");

            console.log("ACTION =", msg.action);
            console.log("PARSED MESSAGE:", msg);

            switch (msg.action) {

                case "AGENT_CONNECTED": {

                    if (!Array.isArray(msg.machineIds)) {
                        console.log("machineIds is not an array");
                        return;
                    }

                    for (const machineId of msg.machineIds) {
                        machineToSocket.set(machineId, ws);

                        console.log(
                            `Mapped machine ${machineId} -> websocket`
                        );
                    }

                    console.log(
                        "Current machine mappings:",
                        [...machineToSocket.keys()]
                    );

                    break;
                }

                case "CHALLENGE_RESPONSE": {

                    console.log(
                        `Processing challenge response for machine ${msg.machine_id}`
                    );

                    await handleChallengeResponse(msg);

                    break;
                }

                default: {

                    console.log(
                        `Unknown WS action received: ${msg.action}`
                    );

                    break;
                }
            }

        } catch (err) {
            console.error("WS message error:", err);
        }
    });

    ws.on("close", () => {
        console.log("================================");
        console.log("AGENT DISCONNECTED");
        console.log("================================");

        for (const [machineId, socket] of machineToSocket.entries()) {

            if (socket === ws) {

                machineToSocket.delete(machineId);

                console.log(
                    `Removed mapping for machine ${machineId}`
                );
            }
        }

        console.log(
            "Remaining mappings:",
            [...machineToSocket.keys()]
        );
    });

    ws.on("error", (err) => {
        console.error("WebSocket error:", err);
    });
});

export function getSocketForMachine(machineId: string) {
    return machineToSocket.get(machineId);
}

export function getAllMappings() {
    return [...machineToSocket.keys()];
}