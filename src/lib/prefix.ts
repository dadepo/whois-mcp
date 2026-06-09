import net from "node:net";

export function validateIpPrefix(prefix: string): void {
  const [address, length, extra] = prefix.split("/");
  if (!address || extra !== undefined) {
    throw new Error(`Invalid IP prefix: ${prefix}`);
  }

  const version = net.isIP(address);
  if (version === 0) {
    throw new Error(`Invalid IP prefix: ${prefix}`);
  }

  if (length === undefined) {
    return;
  }

  if (!/^\d+$/.test(length)) {
    throw new Error(`Invalid IP prefix: ${prefix}`);
  }

  const parsedLength = Number.parseInt(length, 10);
  const maxLength = version === 4 ? 32 : 128;
  if (parsedLength < 0 || parsedLength > maxLength) {
    throw new Error(`Invalid IP prefix: ${prefix}`);
  }
}
