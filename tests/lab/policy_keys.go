package lab

// labPolicyKeys is the keys: block a generated lab policy ends with. port49d
// refuses a policy with no keys: block, and a device whose key_ref the block
// lacks (decision 53 ruling 3), and inventory-lab.yaml assigns every device
// lab_key. The harness sets PORT49_KEY_LAB for the daemons it starts
// (harness_test.go startDaemonWith and proc.start).
const labPolicyKeys = "keys:\n  lab_key:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LAB}\n"
