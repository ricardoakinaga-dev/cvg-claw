const days = Number(process.env.CLOCK_SHIFT_DAYS ?? '0')
const OFFSET = days * 86_400_000
const RealDate = globalThis.Date
class ShiftedDate extends RealDate {
  constructor(...args) {
    if (args.length === 0) super(RealDate.now() + OFFSET)
    else super(...args)
  }
  static [Symbol.hasInstance](value) {
    return value instanceof RealDate
  }
  static now() {
    return RealDate.now() + OFFSET
  }
}
globalThis.Date = ShiftedDate
