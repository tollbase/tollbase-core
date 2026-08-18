import { AgentBlipsClient } from './client';

const ENDPOINT = 'https://agentblips-core.agentblips-spenser.workers.dev';
const AGENT_ID = 'sdk-test-agent-001';

async function main(): Promise<void> {
  const client = new AgentBlipsClient(ENDPOINT, AGENT_ID);

  console.log('--- getStatus() ---');
  const status = await client.getStatus();
  console.log(JSON.stringify(status, null, 2));

  console.log('\n--- sendTelemetry("sdk-heartbeat") ---');
  const result = await client.sendTelemetry('sdk-heartbeat', { test: true });

  if (result.ok) {
    console.log('SUCCESS');
    console.log(JSON.stringify(result.data, null, 2));
    return;
  }

  if (result.paymentRequired) {
    console.log('402 PAYMENT REQUIRED');
    console.log(`code: ${result.challenge.code}`);
    console.log(`message: ${result.challenge.message}`);
    console.log(JSON.stringify(result.challenge, null, 2));
    return;
  }

  console.log(`ERROR (${result.status})`);
  console.log(JSON.stringify(result.error, null, 2));
}

main().catch((error: unknown) => {
  console.error('Test client failed:', error);
  process.exitCode = 1;
});
