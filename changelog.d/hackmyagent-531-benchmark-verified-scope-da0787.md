---
type: fixed
issue: 531
---
#### The `hackmyagent_benchmark` MCP tool says which controls its compliance figure covers (#531)

- The compliance figure counts only the controls that passed or failed. Unverified controls are left out of it, so a run that verified 4 controls could report `100% compliance (Certified)` while a run that verified 23 reported 91%. The headline gave no hint of this.
- The headline now names the controls behind the figure, for example `OASB-1 L1 Assessment: 100% compliance over 4 verified controls (Certified)`. When any control is unverified, a `Coverage:` line follows. It gives how many of the level's controls were verified and says the unverified ones are not counted in the figure. The figure, the rating and the per-control lines are unchanged.
