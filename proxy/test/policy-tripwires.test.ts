import { test, expect, describe } from "bun:test";
import { policySchema } from "../src/policy/schema.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";

const base = { agent: "a", on_behalf_of: "x" };

describe("tripwires schema", () => {
  test("accepts action-only and scoped tripwires", () => {
    const p = policySchema.parse({
      ...base,
      tripwires: [{ action: "*:admin" }, { action: "*:delete", targets: ["prod-*"], note: "no" }],
    });
    expect(p.tripwires!.length).toBe(2);
    expect(p.tripwires![0]!.targets).toBeUndefined();
  });

  test("rejects missing action, empty targets, unknown key", () => {
    expect(() => policySchema.parse({ ...base, tripwires: [{}] })).toThrow();
    expect(() => policySchema.parse({ ...base, tripwires: [{ action: "x", targets: [] }] })).toThrow();
    expect(() => policySchema.parse({ ...base, tripwires: [{ action: "x", bogus: 1 }] })).toThrow();
  });

  test("on_trip defaults to cascade, accepts leaf, rejects anything else", () => {
    const def = policySchema.parse({ ...base, tripwires: [{ action: "*:delete" }] });
    expect(def.tripwires![0]!.on_trip).toBe("cascade"); // default is the blast radius
    const leaf = policySchema.parse({ ...base, tripwires: [{ action: "*:delete", on_trip: "leaf" }] });
    expect(leaf.tripwires![0]!.on_trip).toBe("leaf");
    expect(() => policySchema.parse({ ...base, tripwires: [{ action: "x", on_trip: "root" }] })).toThrow();
    expect(() => policySchema.parse({ ...base, tripwires: [{ action: "x", on_trip: "" }] })).toThrow();
  });
});

describe("tripwires compile", () => {
  test("compiles action + optional targets/note", () => {
    const r = compilePolicyYaml(`
agent: a
on_behalf_of: x
tripwires:
  - action: "*:admin"
  - action: "*:delete"
    targets: ["prod-*"]
    note: "no prod deletes"
`);
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.tripwires.length).toBe(2);
    expect(r.policy.tripwires[0]!.targets).toBeNull();
    expect(r.policy.tripwires[0]!.note).toBeNull();
    expect(r.policy.tripwires[0]!.action.re.test("secrets:admin")).toBe(true);
    expect(r.policy.tripwires[1]!.targets![0]!.re.test("prod-db")).toBe(true);
    expect(r.policy.tripwires[1]!.note).toBe("no prod deletes");
  });

  test("absent tripwires -> empty array", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: x\n`);
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.tripwires).toEqual([]);
  });

  test("onTrip compiles: default cascade, explicit leaf preserved", () => {
    const r = compilePolicyYaml(`
agent: a
on_behalf_of: x
tripwires:
  - action: "*:delete"
  - action: "repo:transfer"
    on_trip: leaf
`);
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.tripwires[0]!.onTrip).toBe("cascade");
    expect(r.policy.tripwires[1]!.onTrip).toBe("leaf");
  });
});
