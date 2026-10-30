// Only for retiring this run's disposable TaskLedger namespace. No bindings or network effects.
export default {fetch(){return new Response('Disposable staging run retired',{status:403})}};
