import type { Metadata } from "next";
import { Code } from "../../../components/Code";
import { LIMITS } from "../../../lib/site";
import { deliveryHeaders, verifyNode, verifyPython } from "../../../lib/snippets";

export const metadata: Metadata = { title: "Delivery & signatures" };

const STATES: [string, string][] = [
  ["scheduled", "Waiting for its time."],
  ["delivering", "An attempt is in flight."],
  ["retrying", "The last attempt failed in a retryable way; the next is scheduled."],
  ["succeeded", "The destination returned 2xx."],
  ["failed", "Gave up: a permanent error, or no attempts left. Can be redriven."],
  ["canceled", "Canceled before it was delivered."],
];

const RETRIES: [string, string][] = [
  ["after attempt 1", "5–10 s"],
  ["after attempt 2", "10–20 s"],
  ["after attempt 3", "20–40 s"],
  ["after attempt 4", "40–80 s"],
];

export default function Delivery() {
  return (
    <>
      <h1>Delivery &amp; signatures</h1>
      <p className="lede">
        What the destination receives, how to check it came from RunLater, and what happens when it fails.
      </p>

      <h2 id="lifecycle">Task lifecycle</h2>
      <div className="table-scroll">
        <table>
          <tbody>
            {STATES.map(([s, d]) => (
              <tr key={s}>
                <td>
                  <code>{s}</code>
                </td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>
        Delivery is <strong>at least once</strong>: if a worker is lost mid-attempt, the attempt is recorded as{" "}
        <code>lease_expired</code> and tried again, so the destination may see the same task twice. Use{" "}
        <code>RunLater-Task-Id</code> to ignore repeats. Timing is best effort, with no exact-time or ordering promise.
      </p>

      <h2 id="request">What the destination receives</h2>
      <p>
        The method, headers and body you scheduled, plus four RunLater headers. Header values you set are sent as
        given.
      </p>
      <Code label="example delivery">{deliveryHeaders}</Code>
      <ul>
        <li>
          <code>RunLater-Task-Id</code> and <code>RunLater-Attempt</code> identify the task and which try this is.
        </li>
        <li>
          <code>RunLater-Timestamp</code> is when the attempt was signed, in unix seconds.
        </li>
        <li>
          <code>RunLater-Signature</code> is <code>v1=</code> followed by the hex HMAC-SHA256 of{" "}
          <code>{"{timestamp}.{task_id}.{attempt}."}</code> and then the raw body, keyed with the project's{" "}
          <code>signing_secret</code>.
        </li>
      </ul>

      <h2 id="verify">Verifying a delivery</h2>
      <p>
        Compute the HMAC over the raw body exactly as received, before any JSON parsing, and compare in constant time.
        Reject timestamps more than five minutes from your clock. While a secret is being rotated, the header holds one{" "}
        <code>v1=</code> entry per active secret; accept a match on any of them.
      </p>
      <Code label="Node.js">{verifyNode}</Code>
      <Code label="Python">{verifyPython}</Code>
      <p className="muted">Both samples are run in RunLater's test suite against a fixed signature.</p>

      <h2 id="callbacks">Callbacks</h2>
      <p>
        Pass <code>callback_url</code> to <code>schedule_http</code> and RunLater tells you how the task ended instead of
        you polling <code>get_task</code>. Each time the task succeeds, fails or is canceled, a <em>callback task</em>{" "}
        <code>POST</code>s <code>{'{"event": "task.finished", "task": {…}}'}</code> to that URL, where{" "}
        <code>task</code> is the task as <code>get_task</code> returns it, attempts included.
      </p>
      <ul>
        <li>
          It is signed and retried like any delivery: verify it the same way. Its <code>RunLater-Task-Id</code> is the
          callback task's id; the task being reported on is <code>task.id</code> in the body.
        </li>
        <li>
          The task shows the callback's id as <code>callback_task_id</code>; the callback task shows the original as{" "}
          <code>callback_for</code>. A redriven task calls back again when it finishes again.
        </li>
        <li>
          Each callback try costs one delivery attempt, so a task with a callback reserves two attempts when it is
          scheduled.
        </li>
      </ul>

      <h2 id="retries">Retries</h2>
      <p>
        <strong>Retried:</strong> timeouts, network errors, and HTTP 408, 425, 429 and 5xx. <strong>Not retried:</strong>{" "}
        other 4xx responses and redirects (3xx), which are never followed. A task has 1–5 attempts (default 5) and each
        has 10 seconds.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Wait</th>
              <th>Delay</th>
            </tr>
          </thead>
          <tbody>
            {RETRIES.map(([w, d]) => (
              <tr key={w}>
                <td>{w}</td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>
        The delay doubles each time from 10 seconds, capped at 10 minutes, and is randomized between half and the full
        value. A <code>Retry-After</code> header in seconds sets a minimum, up to the same cap. Every attempt costs one
        of the trial's delivery attempts.
      </p>

      <h2 id="destinations">Allowed destinations</h2>
      <ul>
        <li>
          <code>https://</code> on the default port, to a public DNS name.
        </li>
        <li>
          No IP addresses, usernames or passwords in the URL, or <code>#fragments</code>.
        </li>
        <li>
          No private names such as <code>localhost</code>, <code>*.local</code>, <code>*.internal</code> or{" "}
          <code>*.test</code>. Names that resolve to private addresses are refused by the network as well.
        </li>
        <li>
          You can't set <code>Host</code>, <code>Content-Length</code>, <code>Transfer-Encoding</code> or similar
          headers, or any <code>RunLater-*</code>, <code>CF-*</code>, <code>X-Forwarded-*</code> or{" "}
          <code>Proxy-*</code> header. <code>GET</code> requests can't have a body.
        </li>
      </ul>
      <p>The URL is checked when the task is scheduled and again before every attempt.</p>

      <h2 id="limits">Limits</h2>
      <div className="table-scroll">
        <table>
          <tbody>
            {LIMITS.map(([k, v]) => (
              <tr key={k}>
                <th scope="row">{k}</th>
                <td>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
