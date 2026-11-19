// SPDX-License-Identifier: Apache-2.0
/**
 * Reachability over a lockfile's dependency graph: which entries a set of
 * roots installs, directly or through any chain of dependencies. Nodes are
 * numbered as they are first named and edges are kept as two flat number
 * lists, so a 150,000-entry lockfile costs two numbers per edge, not an
 * object.
 */

/** A dependency graph by node number. */
export class ScopeGraph {
  private ids = new Map<string, number>();
  private from: number[] = [];
  private to: number[] = [];

  /** The node for `key`, created on first sight. */
  node(key: string): number {
    let id = this.ids.get(key);
    if (id === undefined) {
      id = this.ids.size;
      this.ids.set(key, id);
    }
    return id;
  }

  /** The node for `key` when one exists. */
  find(key: string): number | undefined {
    return this.ids.get(key);
  }

  get size(): number {
    return this.ids.size;
  }

  edge(from: number, to: number): void {
    this.from.push(from);
    this.to.push(to);
  }

  /** True when every edge points at a node `known` accepts. */
  everyTarget(known: (node: number) => boolean): boolean {
    return this.to.every(known);
  }

  /** `reached[node] === 1` for every node `roots` reach, themselves included. */
  reach(roots: Iterable<number>): Uint8Array {
    const n = this.ids.size;
    // Adjacency as offsets into one array: no array per node.
    const start = new Int32Array(n + 1);
    for (const f of this.from) start[f + 1]++;
    for (let i = 0; i < n; i++) start[i + 1] += start[i];
    const fill = start.slice(0, n);
    const targets = new Int32Array(this.to.length);
    for (let i = 0; i < this.from.length; i++) targets[fill[this.from[i]]++] = this.to[i];
    const reached = new Uint8Array(n);
    const stack: number[] = [];
    for (const root of roots) {
      if (root < n && reached[root] === 0) {
        reached[root] = 1;
        stack.push(root);
      }
    }
    while (stack.length > 0) {
      const at = stack.pop() as number;
      for (let i = start[at]; i < start[at + 1]; i++) {
        const next = targets[i];
        if (reached[next] === 0) {
          reached[next] = 1;
          stack.push(next);
        }
      }
    }
    return reached;
  }
}
