/**
 * create_generators (draft §Generators Calculation) for BLS12-381-SHA-256.
 * Deterministic: seeded expand_message_xmd chain, each state hashed to G1.
 */
import { bls12_381 } from '@noble/curves/bls12-381'
import {
  API_ID,
  CIPHERSUITE_ID,
  EXPAND_LEN,
  G1,
  type G1Point,
  ascii,
  concat,
  expandMessage,
  i2osp,
} from './ciphersuite'

function hashToCurveG1(msg: Uint8Array, dst: Uint8Array): G1Point {
  const p = bls12_381.G1.hashToCurve(msg, { DST: dst })
  return G1.fromAffine(p.toAffine())
}

export function createGenerators(count: number, apiId: string, seedTag = 'MESSAGE_GENERATOR_SEED'): G1Point[] {
  const seedDst = ascii(apiId + 'SIG_GENERATOR_SEED_')
  const generatorDst = ascii(apiId + 'SIG_GENERATOR_DST_')
  let v = expandMessage(ascii(apiId + seedTag), seedDst, EXPAND_LEN)
  const generators: G1Point[] = []
  for (let i = 1; i <= count; i++) {
    v = expandMessage(concat(v, i2osp(i, 8)), seedDst, EXPAND_LEN)
    generators.push(hashToCurveG1(v, generatorDst))
  }
  return generators
}

// Interface generators are constants — cache and extend on demand.
const cache: G1Point[] = []
export function interfaceGenerators(count: number): G1Point[] {
  if (cache.length < count) {
    cache.length = 0
    cache.push(...createGenerators(count, API_ID))
  }
  return cache.slice(0, count)
}

/**
 * P1, the ciphersuite's fixed G1 base: create_generators(1) with the
 * "BP_MESSAGE_GENERATOR_SEED" seed (draft §BLS12-381 Ciphersuites). Computed
 * once here and pinned against the fixture hex by a KAT.
 */
export const P1: G1Point = createGenerators(1, CIPHERSUITE_ID + 'H2G_HM2S_', 'BP_MESSAGE_GENERATOR_SEED')[0]
