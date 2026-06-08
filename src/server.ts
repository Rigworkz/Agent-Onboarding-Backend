import app from "./app";
import dotenv from "dotenv";
import "./websocket/socketServer";

dotenv.config();

const PORT = Number(process.env.PORT) || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is running on port ${PORT}`);
});
