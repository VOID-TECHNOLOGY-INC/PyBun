//! Persisted identity alignment, independent of current lexical advisory IDs.
use super::{model::*, projection::ObservedFinding, state::*};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Alignment {
    pub index: Option<usize>,
    pub correction: Option<&'static str>,
}
fn root(snapshot: &Snapshot, mut index: usize) -> MonitorResult<usize> {
    for _ in 0..=snapshot.lineages.len() {
        let Some(parent) = &snapshot.lineages[index].merged_into else {
            return Ok(index);
        };
        index = snapshot
            .lineages
            .iter()
            .position(|node| &node.finding.finding_id == parent)
            .ok_or_else(|| MonitorError::new("E_MONITOR_STATE_CORRUPT"))?;
    }
    Err(MonitorError::new("E_MONITOR_STATE_CORRUPT"))
}
pub(crate) fn align(
    snapshot: &mut Snapshot,
    observed: &[ObservedFinding],
) -> MonitorResult<Vec<Alignment>> {
    let mut result = Vec::new();
    for item in observed {
        let aliases: BTreeSet<_> = item.value.aliases.iter().cloned().collect();
        if !item.identity_authoritative {
            let aliases = if item.fresh_aliases.is_empty() {
                &aliases
            } else {
                &item.fresh_aliases
            };
            let index = snapshot
                .lineages
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    node.merged_into.is_none()
                        && node.finding.package_key == item.value.package_key
                        && !node.known_aliases.is_disjoint(aliases)
                })
                .min_by_key(|(_, node)| node.ordinal)
                .map(|(index, _)| index);
            result.push(Alignment {
                index,
                correction: None,
            });
            continue;
        }
        let candidates: Vec<_> = snapshot
            .lineages
            .iter()
            .enumerate()
            .filter(|(_, node)| node.finding.package_key == item.value.package_key)
            .collect();
        let current: Vec<_> = candidates
            .iter()
            .filter(|(_, node)| !node.current_aliases.is_disjoint(&aliases))
            .map(|(i, _)| *i)
            .collect();
        let matched = if current.is_empty() {
            candidates
                .iter()
                .filter(|(_, node)| !node.known_aliases.is_disjoint(&aliases))
                .map(|(i, _)| *i)
                .collect()
        } else {
            current
        };
        let mut roots = BTreeSet::new();
        for index in matched {
            roots.insert(root(snapshot, index)?);
        }
        let winner = roots
            .iter()
            .copied()
            .min_by_key(|i| snapshot.lineages[*i].ordinal);
        let merging = roots.len() > 1;
        if let Some(winner) = winner {
            for loser in roots.into_iter().filter(|i| *i != winner) {
                let other = snapshot.lineages[loser].clone();
                let winner_id = snapshot.lineages[winner].finding.finding_id.clone();
                snapshot.lineages[loser].merged_into = Some(winner_id);
                let node = &mut snapshot.lineages[winner];
                node.known_aliases.extend(other.known_aliases);
                node.finding.active |= other.finding.active;
                if node.finding.candidate.is_none()
                    || node
                        .finding
                        .candidate
                        .as_ref()
                        .is_some_and(|candidate| !candidate.qualified_remediation)
                        && other
                            .finding
                            .candidate
                            .as_ref()
                            .is_some_and(|candidate| candidate.qualified_remediation)
                {
                    node.finding.candidate = other.finding.candidate;
                }
                if other
                    .finding
                    .last_known_severity
                    .and_then(|level| level.rank())
                    > node
                        .finding
                        .last_known_severity
                        .and_then(|level| level.rank())
                {
                    node.finding.last_known_severity = other.finding.last_known_severity;
                }
                node.finding.evidence.extend(other.finding.evidence);
                node.finding
                    .vulnerable_versions
                    .extend(other.finding.vulnerable_versions);
                node.finding.vulnerable_versions.sort();
                node.finding.vulnerable_versions.dedup();
                node.finding.related_lineages.push(other.finding.finding_id);
                node.finding.related_lineages.sort();
                node.finding.related_lineages.dedup();
            }
        }
        result.push(Alignment {
            index: winner,
            correction: merging.then_some("alias_merge"),
        });
    }
    // Earlier merges may have absorbed an index selected by another component.
    for item in &mut result {
        if let Some(index) = item.index {
            item.index = Some(root(snapshot, index)?);
        }
    }
    let mut uses: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (position, item) in result.iter().enumerate() {
        if !observed[position].identity_authoritative {
            continue;
        }
        if let Some(index) = item.index {
            uses.entry(index).or_default().push(position);
        }
    }
    for (parent, positions) in uses
        .into_iter()
        .filter(|(_, positions)| positions.len() > 1)
    {
        let parent_id = snapshot.lineages[parent].finding.finding_id.clone();
        let main = positions
            .iter()
            .copied()
            .find(|position| {
                observed[*position]
                    .value
                    .aliases
                    .contains(&snapshot.lineages[parent].anchor)
            })
            .unwrap_or(positions[0]);
        let mut assigned = BTreeSet::from([parent]);
        for position in positions {
            result[position].correction = Some("alias_split");
            if position == main {
                continue;
            }
            let aliases: BTreeSet<_> = observed[position].value.aliases.iter().cloned().collect();
            let existing = snapshot
                .lineages
                .iter()
                .enumerate()
                .filter(|(index, node)| {
                    !assigned.contains(index)
                        && node.finding.package_key == observed[position].value.package_key
                        && aliases.contains(&node.anchor)
                })
                .min_by_key(|(_, node)| node.ordinal)
                .map(|(index, _)| index);
            let index = if let Some(index) = existing {
                snapshot.lineages[index].merged_into = None;
                snapshot.lineages[index].finding.active = snapshot.lineages[parent].finding.active;
                index
            } else {
                let mut node = snapshot.lineages[parent].clone();
                snapshot.lineage_counter = snapshot
                    .lineage_counter
                    .checked_add(1)
                    .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
                node.ordinal = snapshot.lineage_counter;
                node.anchor = observed[position].value.aliases[0].clone();
                node.known_aliases = aliases.clone();
                node.current_aliases = aliases;
                node.parents = vec![parent_id.clone()];
                node.merged_into = None;
                node.finding.finding_id = random_id();
                node.finding.related_lineages = vec![parent_id.clone()];
                snapshot.lineages.push(node);
                snapshot.lineages.len() - 1
            };
            assigned.insert(index);
            if !snapshot.lineages[index]
                .finding
                .related_lineages
                .contains(&parent_id)
            {
                snapshot.lineages[index]
                    .finding
                    .related_lineages
                    .push(parent_id.clone());
            }
            result[position].index = Some(index);
        }
    }
    Ok(result)
}
