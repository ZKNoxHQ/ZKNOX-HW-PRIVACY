// Line-oriented BLAKE-512 oracle (hex in, hex out), used by reference.py so the
// Python side does not need its own BLAKE-1 implementation.
import { createInterface } from 'node:readline'
import { blake512 } from '@noble/hashes/blake1.js'

const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
  const t = line.trim()
  const b = t.length === 0 ? new Uint8Array(0) : Uint8Array.from(Buffer.from(t, 'hex'))
  process.stdout.write(Buffer.from(blake512(b)).toString('hex') + '\n')
})
