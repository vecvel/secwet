//! Workspace tree inspection command for humans and AI agents.

use clap::Args;
use secwet_core::{Error, Result, Secwet};
use serde::Serialize;
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct TreeArgs {
    /// Filter workspace tree by space name or UUID
    #[arg(long)]
    pub space: Option<String>,

    /// Output the entire workspace hierarchy in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct TreeRoot {
    spaces: Vec<TreeSpace>,
}

#[derive(Serialize)]
struct TreeSpace {
    id: Uuid,
    name: String,
    is_default: bool,
    icon: Option<String>,
    groups: Vec<TreeGroup>,
}

#[derive(Serialize)]
struct TreeGroup {
    id: Uuid,
    name: String,
    icon: Option<String>,
    items: Vec<TreeItem>,
}

#[derive(Serialize)]
struct TreeItem {
    id: Uuid,
    name: String,
    description: Option<String>,
    environments: Vec<TreeEnv>,
    secrets: Vec<TreeSecret>,
    notes: Vec<TreeNote>,
    files: Vec<TreeFile>,
}

#[derive(Serialize)]
struct TreeEnv {
    id: Uuid,
    name: String,
    secret_count: usize,
}

#[derive(Serialize)]
struct TreeSecret {
    id: Uuid,
    name: String,
    kind: String,
    tail: String,
    note: Option<String>,
    in_use: bool,
}

#[derive(Serialize)]
struct TreeNote {
    id: Uuid,
    title: String,
}

#[derive(Serialize)]
struct TreeFile {
    id: Uuid,
    name: String,
    size_bytes: u64,
}

pub fn execute_tree(secwet: &Secwet, args: TreeArgs) -> Result<()> {
    let spaces = if let Some(ref sp_target) = args.space {
        let sp = crate::commands::space::resolve_space(secwet, sp_target)?;
        vec![sp]
    } else {
        secwet.list_spaces()?
    };

    let active_sessions = secwet.list_active_sessions().unwrap_or_default();
    let mut tree_spaces = Vec::new();

    for sp in spaces {
        let labels = secwet.list_labels_by_space(sp.id).unwrap_or_default();
        let mut tree_groups = Vec::new();

        for l in labels {
            let items = secwet.list_items(l.id).unwrap_or_default();
            let mut tree_items = Vec::new();

            for it in items {
                let envs = secwet.list_environments(it.id).unwrap_or_default();
                let mut secrets_list = secwet.list_secrets(it.id, None).unwrap_or_default();
                for env in &envs {
                    if let Ok(env_secrets) = secwet.list_secrets(it.id, Some(env.id)) {
                        for s in env_secrets {
                            if !secrets_list.iter().any(|existing| existing.id == s.id) {
                                secrets_list.push(s);
                            }
                        }
                    }
                }

                let mut notes_list = secwet.list_notes(it.id, None).unwrap_or_default();
                for env in &envs {
                    if let Ok(env_notes) = secwet.list_notes(it.id, Some(env.id)) {
                        for n in env_notes {
                            if !notes_list.iter().any(|existing| existing.id == n.id) {
                                notes_list.push(n);
                            }
                        }
                    }
                }

                let mut files_list = secwet.list_files(it.id, None).unwrap_or_default();
                for env in &envs {
                    if let Ok(env_files) = secwet.list_files(it.id, Some(env.id)) {
                        for f in env_files {
                            if !files_list.iter().any(|existing| existing.id == f.id) {
                                files_list.push(f);
                            }
                        }
                    }
                }

                let tree_envs = envs
                    .into_iter()
                    .map(|e| TreeEnv {
                        id: e.id,
                        name: e.name,
                        secret_count: e.secret_count,
                    })
                    .collect();

                let tree_secrets = secrets_list
                    .into_iter()
                    .map(|s| {
                        let in_use = active_sessions.iter().any(|sess| sess.secret_ids.contains(&s.id));
                        TreeSecret {
                            id: s.id,
                            name: s.name,
                            kind: s.kind.to_string(),
                            tail: s.value_tail,
                            note: s.note,
                            in_use,
                        }
                    })
                    .collect();

                let tree_notes = notes_list
                    .into_iter()
                    .map(|n| TreeNote {
                        id: n.id,
                        title: n.title,
                    })
                    .collect();

                let tree_files = files_list
                    .into_iter()
                    .map(|f| TreeFile {
                        id: f.id,
                        name: f.name,
                        size_bytes: f.size_bytes,
                    })
                    .collect();

                tree_items.push(TreeItem {
                    id: it.id,
                    name: it.name,
                    description: it.description,
                    environments: tree_envs,
                    secrets: tree_secrets,
                    notes: tree_notes,
                    files: tree_files,
                });
            }

            tree_groups.push(TreeGroup {
                id: l.id,
                name: l.name,
                icon: l.icon,
                items: tree_items,
            });
        }

        tree_spaces.push(TreeSpace {
            id: sp.id,
            name: sp.name,
            is_default: sp.is_default,
            icon: sp.icon,
            groups: tree_groups,
        });
    }

    if args.json {
        let root = TreeRoot { spaces: tree_spaces };
        println!("{}", serde_json::to_string_pretty(&root).map_err(|_| Error::Storage)?);
    } else {
        println!("Secwet Workspace");
        if tree_spaces.is_empty() {
            println!("  (No spaces found)");
            return Ok(());
        }

        for (s_idx, s) in tree_spaces.iter().enumerate() {
            let is_last_s = s_idx == tree_spaces.len() - 1;
            let s_prefix = if is_last_s { "└──" } else { "├──" };
            let s_indent = if is_last_s { "    " } else { "│   " };

            let def_tag = if s.is_default { " [default]" } else { "" };
            let icon_str = s.icon.as_deref().map(|i| format!(" [{i}]")).unwrap_or_default();
            println!("{s_prefix} Space: {}{}{}", s.name, def_tag, icon_str);

            if s.groups.is_empty() {
                println!("{s_indent}└── (No groups)");
                continue;
            }

            for (g_idx, g) in s.groups.iter().enumerate() {
                let is_last_g = g_idx == s.groups.len() - 1;
                let g_prefix = if is_last_g { "└──" } else { "├──" };
                let g_indent = if is_last_g { "    " } else { "│   " };

                let g_icon_str = g.icon.as_deref().map(|i| format!(" [{i}]")).unwrap_or_default();
                println!("{s_indent}{g_prefix} Group: {}{}", g.name, g_icon_str);

                if g.items.is_empty() {
                    println!("{s_indent}{g_indent}└── (No items)");
                    continue;
                }

                for (i_idx, it) in g.items.iter().enumerate() {
                    let is_last_i = i_idx == g.items.len() - 1;
                    let i_prefix = if is_last_i { "└──" } else { "├──" };
                    let i_indent = if is_last_i { "    " } else { "│   " };

                    println!("{s_indent}{g_indent}{i_prefix} Item: {}", it.name);

                    // Envs
                    if !it.environments.is_empty() {
                        let env_names: Vec<String> = it.environments.iter().map(|e| e.name.clone()).collect();
                        println!("{s_indent}{g_indent}{i_indent}├── Environments: [{}]", env_names.join(", "));
                    }

                    // Secrets
                    let sec_str = if it.secrets.is_empty() {
                        "None".to_string()
                    } else {
                        let names: Vec<String> = it.secrets.iter().map(|s| {
                            if s.in_use {
                                format!("{} ({}) [In use]", s.name, s.kind)
                            } else {
                                format!("{} ({})", s.name, s.kind)
                            }
                        }).collect();
                        names.join(", ")
                    };
                    println!("{s_indent}{g_indent}{i_indent}├── Secrets ({}): {}", it.secrets.len(), sec_str);

                    // Notes
                    println!("{s_indent}{g_indent}{i_indent}├── Notes ({})", it.notes.len());

                    // Files
                    println!("{s_indent}{g_indent}{i_indent}└── Files ({})", it.files.len());
                }
            }
        }
    }

    Ok(())
}
