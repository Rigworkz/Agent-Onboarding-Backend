import express from "express";
import cors from "cors";
import helmet from "helmet";
import routes from "./routes";
import { setupSwagger } from "./swagger";
import path from "path";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());


app.use("/scripts", express.static(path.join(__dirname, "../public/scripts")));

app.use("/api", routes);

setupSwagger(app);

export default app;
