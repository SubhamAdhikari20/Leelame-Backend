// backend/utils/knock.js
import Knock from "@knocklabs/node";

const knock = new Knock(process.env.KNOCK_API_KEY);
export default knock;