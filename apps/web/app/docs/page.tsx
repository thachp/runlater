import type { Metadata } from "next";
import Link from "next/link";
import { Code } from "../../components/Code";
import { GATEWAY_URL } from "../../lib/site";
import { mcpConfig, sdkExample } from "../../lib/snippets";

export const metadata: Metadata = { title: "Quickstart" };

export default function Quickstart() {
  return (
    <>
      <h1>Quickstart</h1>
      <p className="lede">
        Connect an agent, create a project, schedule a request, check it later. Two ways in: from an MCP client, or
        from code with the Agent Auth SDK.
      </p>

      <div className="callout">
        <p>
          <strong>Free trial.</strong> Each agent gets one project with 100 delivery attempts over 7 days. Paid plans
          aren't available yet.
        </p>
      </div>

      <h2 id="identity">How agents sign in</h2>
      <p>
        RunLater uses <a href="https://agentauthprotocol.com">Agent Auth</a>. An agent generates its own keys and
        registers them with the gateway; there is no account, password or API key. Each identity gets one project
        with a free trial. Discovery is at <code>{GATEWAY_URL}/.well-known/agent-configuration</code>.
      </p>
      <p>
        <strong>Keep the keys.</strong> The project belongs to the key that created it. If the keys are lost, so is
        access to the project.
      </p>

      <h2 id="mcp">From an MCP client</h2>
      <p>
        Add the Agent Auth bridge as a local MCP server. It runs on your machine, stores the agent's keys in{" "}
        <code>~/.agent-auth</code> (encrypted with the key you set), and talks to RunLater for you.
      </p>
      <Code label="claude_desktop_config.json, or your client's MCP settings">{mcpConfig}</Code>
      <p>
        The bridge offers generic Agent Auth tools rather than one tool per RunLater feature. Ask the agent to schedule
        something with RunLater and it will:
      </p>
      <ol>
        <li>
          call <code>connect_agent</code> with provider <code>{GATEWAY_URL}</code>,
        </li>
        <li>
          use <code>list_capabilities</code> to read what RunLater offers,
        </li>
        <li>
          call <code>execute_capability</code> with <code>create_project</code>, then <code>schedule_http</code>, and
          later <code>get_task</code>.
        </li>
      </ol>
      <p className="muted">
        MCP clients that only support remote servers can't run the bridge yet.
      </p>

      <h2 id="sdk">From code</h2>
      <p>
        Use <code>@auth/agent</code> in TypeScript or JavaScript. Every RunLater feature is a capability you execute
        by name; results come back in <code>data</code>.
      </p>
      <Code label="agent.mjs">{sdkExample}</Code>

      <h2 id="new-capabilities">When RunLater adds a capability</h2>
      <p>
        An agent is granted the capabilities that existed when it connected. When RunLater adds one, such as the cron
        tools (<code>create_cron</code>, <code>get_cron</code>, <code>list_crons</code>, <code>delete_cron</code>),
        an agent that connected earlier gets <code>capability_not_granted</code> until it asks for it once. The grant
        is immediate; nobody has to approve it.
      </p>
      <ul>
        <li>
          From the MCP bridge, the agent calls <code>request_capability</code> with its <code>agent_id</code> and the
          new capability names. The bridge tells agents to do this on <code>capability_not_granted</code>.
        </li>
        <li>
          From code, call <code>client.requestCapability({"{ agentId, capabilities: [\"create_cron\", \"get_cron\", \"list_crons\", \"delete_cron\"] }"})</code>.
        </li>
      </ul>
      <p>The project, its tasks and its keys stay the same; there is no need to connect again.</p>

      <h2 id="next">Next</h2>
      <ul>
        <li>
          <Link href="/docs/capabilities">Capabilities</Link>: every argument, result and error.
        </li>
        <li>
          <Link href="/docs/delivery">Delivery &amp; signatures</Link>: what the destination receives, how to verify
          it, and when RunLater retries.
        </li>
      </ul>
    </>
  );
}
