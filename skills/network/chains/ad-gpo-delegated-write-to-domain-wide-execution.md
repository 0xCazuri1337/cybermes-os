# Delegated GPO write to domain-wide code execution

> goal: `Convert write access delegated on one widely-linked Group Policy Object into code execution on every host that policy applies to, without holding a privileged group membership.`
> generated from `db/wks.db` — edit the rows, not this file

GPO write rights are delegable to ordinary domain users, and a single edit to a widely-scoped policy's scheduled-task preferences becomes execution across that policy's entire link scope.

## Impact

Domain-wide code execution from a non-administrator account, bounded only by the GPO's link scope, security filtering and WMI filters.

## Sequence

### 1. Obtain a principal holding delegated write, edit or apply permission on a GPO that is linked at domain or site scope.

**Why it works:** GPO access controls can be delegated to specific users or groups, so the authority to change policy does not require domain admin membership; the default is read for all user accounts and write for nobody, so any such delegation is a deliberate exception.

### 2. Edit the GPO's scheduled-task preference XML to add a task that executes attacker-controlled code.

**Why it works:** Publicly available scripts such as New-GPOImmediateTask automate the creation of a malicious Scheduled Task/Job by modifying the GPO's Machine Preferences ScheduledTasks.xml, and malicious GPO modifications can implement behaviours including Scheduled Task/Job, Create Account and Service Execution.

### 3. Wait for, or force, group policy refresh so the modified settings apply to every host in the GPO's link scope.

**Why it works:** Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse, so the blast radius is the policy's applied host set rather than the single edited object.
