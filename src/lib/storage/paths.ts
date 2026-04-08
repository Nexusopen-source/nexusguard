import path from "node:path";

function resolveFromCwd(value: string) {
  return path.isAbsolute(value) ? value : path.join(process.cwd(), value);
}

export function getNexusGuardStoreDir() {
  const configured = process.env.NEXUSGUARD_STORE_DIR?.trim();
  if (configured) {
    return resolveFromCwd(configured);
  }

  if (process.env.VERCEL === "1") {
    return path.join("/tmp", "nexusguard");
  }

  return path.join(process.cwd(), ".nexusguard");
}

export function getNexusGuardStorePath(fileName: string) {
  return path.join(getNexusGuardStoreDir(), fileName);
}