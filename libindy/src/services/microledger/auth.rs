use services::microledger::constants::*;
use std::collections::HashSet;

pub struct Auth {}

impl Auth {
    // TODO: have a static list of auths
    pub fn is_valid_auth(auth: &str) -> bool {
        match auth {
            AUTHZ_ALL => true,
            AUTHZ_ADD_KEY => true,
            AUTHZ_REM_KEY => true,
            AUTHZ_MPROX => true,
            _ => false
        }
    }

    pub fn get_all() -> HashSet<String> {
        let mut s: HashSet<String> = HashSet::new();
        s.insert(AUTHZ_ADD_KEY.to_string());
        s.insert(AUTHZ_REM_KEY.to_string());
        s.insert(AUTHZ_MPROX.to_string());
        s
    }

    pub fn get_auth_changes(subj_auths: &Vec<String>, proposed_auths: &Vec<String>) -> (bool, bool) {
        let mut adding_new_auths = false;
        let mut removing_old_auths = false;
        let existing_auths: HashSet<String> = subj_auths.iter().cloned().collect();
        for pa in proposed_auths {
            if !existing_auths.contains(pa) {
                adding_new_auths = true;
                break;
            }
        }
        let prop_auths: HashSet<String> = proposed_auths.iter().cloned().collect();
        for sa in subj_auths {
            if !prop_auths.contains(sa) {
                removing_old_auths = true;
                break;
            }
        }
        (adding_new_auths, removing_old_auths)
    }

    pub fn can_make_auth_changes(adding_new_auths: bool, removing_old_auths: bool,
                                 actor_auths: &Vec<String>, subject_vk: &str, actor_vk: &str) -> bool {
        if adding_new_auths && !(actor_auths.contains(&AUTHZ_ALL.to_string()) ||
            actor_auths.contains(&AUTHZ_ADD_KEY.to_string())) {
            return false
        }
        if removing_old_auths && !(actor_auths.contains(&AUTHZ_ALL.to_string()) ||
            actor_auths.contains(&AUTHZ_REM_KEY.to_string()) || subject_vk == actor_vk) {
            return false
        }
        true
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_valid_auths() {
        let a1 = "all1";
        let a2 = "al";
        let a3 = "addkey";
        let a4 = "remkey";
        let a5 = "m_prox";
        let a6 = "all";
        let a7 = "add_key";
        let a8 = "rem_key";
        let a9 = "mprox";
        assert_eq!(Auth::is_valid_auth(a1), false);
        assert_eq!(Auth::is_valid_auth(a2), false);
        assert_eq!(Auth::is_valid_auth(a3), false);
        assert_eq!(Auth::is_valid_auth(a4), false);
        assert_eq!(Auth::is_valid_auth(a5), false);
        assert_eq!(Auth::is_valid_auth(a6), true);
        assert_eq!(Auth::is_valid_auth(a7), true);
        assert_eq!(Auth::is_valid_auth(a8), true);
        assert_eq!(Auth::is_valid_auth(a9), true);
    }

    #[test]
    fn test_get_all_auths() {
        let expected: HashSet<String> = [AUTHZ_ADD_KEY.to_string(), AUTHZ_REM_KEY.to_string(),
            AUTHZ_MPROX.to_string()].iter().cloned().collect();
        assert_eq!(Auth::get_all(), expected);
    }

    #[test]
    fn test_get_auth_changes() {
        let old_auths_1 = vec![AUTHZ_ALL.to_string()];
        let new_auths_1 = vec![AUTHZ_ALL.to_string()];
        assert_eq!((false, false), Auth::get_auth_changes(&old_auths_1, &new_auths_1));

        let old_auths_2 = vec![AUTHZ_ADD_KEY.to_string()];
        let new_auths_2 = vec![AUTHZ_ADD_KEY.to_string(), AUTHZ_REM_KEY.to_string()];
        assert_eq!((true, false), Auth::get_auth_changes(&old_auths_2, &new_auths_2));

        let old_auths_3 = vec![AUTHZ_ADD_KEY.to_string(), AUTHZ_REM_KEY.to_string()];
        let new_auths_3 = vec![AUTHZ_ADD_KEY.to_string()];
        assert_eq!((false, true), Auth::get_auth_changes(&old_auths_3, &new_auths_3));

        let old_auths_4 = vec![AUTHZ_ADD_KEY.to_string()];
        let new_auths_4 = vec![AUTHZ_REM_KEY.to_string(), AUTHZ_MPROX.to_string()];
        assert_eq!((true, true), Auth::get_auth_changes(&old_auths_4, &new_auths_4));
    }

    #[test]
    fn test_can_make_auth_changes() {
        let subject_vk = "6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1";
        let actor_vk = "4AdS22kC7xzb4bcqg9JATuCfAMNcQYcZa1u5eWzs6cSJ";

        let actor_auths_1 = vec![AUTHZ_ALL.to_string()];
        assert!(Auth::can_make_auth_changes(false, false, &actor_auths_1, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(true, false, &actor_auths_1, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(false, true, &actor_auths_1, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(true, true, &actor_auths_1, subject_vk, actor_vk));

        let actor_auths_2 = vec![AUTHZ_ADD_KEY.to_string()];
        assert!(Auth::can_make_auth_changes(false, false, &actor_auths_2, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(true, false, &actor_auths_2, subject_vk, actor_vk));
        assert_eq!(Auth::can_make_auth_changes(true, true, &actor_auths_2, subject_vk, actor_vk), false);
        assert_eq!(Auth::can_make_auth_changes(false, true, &actor_auths_2, subject_vk, actor_vk), false);

        let actor_auths_3 = vec![AUTHZ_REM_KEY.to_string()];
        assert!(Auth::can_make_auth_changes(false, false, &actor_auths_3, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(false, true, &actor_auths_3, subject_vk, actor_vk));
        assert_eq!(Auth::can_make_auth_changes(true, true, &actor_auths_3, subject_vk, actor_vk), false);
        assert_eq!(Auth::can_make_auth_changes(true, false, &actor_auths_3, subject_vk, actor_vk), false);

        // Works same as AUTHZ_ALL
        let actor_auths_4 = vec![AUTHZ_ADD_KEY.to_string(), AUTHZ_REM_KEY.to_string()];
        assert!(Auth::can_make_auth_changes(false, false, &actor_auths_4, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(true, false, &actor_auths_4, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(false, true, &actor_auths_4, subject_vk, actor_vk));
        assert!(Auth::can_make_auth_changes(true, true, &actor_auths_4, subject_vk, actor_vk));

        // Subject is same as actor but no relevant permissions
        let actor_auths_5 = vec![AUTHZ_MPROX.to_string()];
        assert!(Auth::can_make_auth_changes(false, false, &actor_auths_5, subject_vk, subject_vk));
        assert!(Auth::can_make_auth_changes(false, true, &actor_auths_5, subject_vk, subject_vk));
        assert_eq!(Auth::can_make_auth_changes(true, true, &actor_auths_5, subject_vk, subject_vk), false);
        assert_eq!(Auth::can_make_auth_changes(true, false, &actor_auths_5, subject_vk, subject_vk), false);
    }
}
