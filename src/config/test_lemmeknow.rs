#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lemmeknow_default_works() {
        let identifier = Identifier::default();
        let result = identifier.identify("192.168.1.1");
        assert!(!result.is_empty(), "LemmeKnow default failed to identify IP");
    }
}
