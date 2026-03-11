import { useEffect } from "react";
import { useTrafficStore } from "../store/trafficstore";

function WebSocketComponent() {
    const addflow = useTrafficStore((state) => state.addflow);
    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8000');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            addflow(data);
        };
    }, [addflow]);
}
export default WebSocketComponent;