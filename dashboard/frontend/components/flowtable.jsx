import { useTrafficStore } from "../store/trafficstore";

export default function FlowTable(){

  const flows = useTrafficStore(s=>s.flows);
  console.log(flows)

  return(

  <table className="w-full text-sm">

    <thead className="text-gray-400">
      <tr>
        <th>Attack</th>
        <th>Score</th>
        <th>Severity</th>
      </tr>
    </thead>

    <tbody>

      {flows.map((f,i)=>(
        <tr key={i} className="border-t border-gray-700">
          {/* <td>{f.final.attack_type}</td>
          <td>{f.final.final_score}</td>
          <td>{f.final.severity}</td> */}
        </tr>
      ))}

    </tbody>

  </table>

  )

}