#[cfg(test)]
mod tests {
    use ciphey::perform_cracking;
    use ciphey::config::Config;
    use ciphey::set_test_db_path;
    use ciphey::TestDatabase;

    #[test]
    fn integration_hash_crack_md5() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let config = Config::default();
        // MD5 of "password"
        let input = "5f4dcc3b5aa765d61d8327deb882cf99";
        let result = perform_cracking(input, config);
        
        assert!(result.is_some(), "Should decode MD5 hash");
        let decoded = result.unwrap();
        // The result text should be "password"
        // Check if any of the results match
        assert!(decoded.text.contains(&"password".to_string()), "Result should contain 'password', found {:?}", decoded.text);
    }

    #[test]
    fn integration_jwt_decode() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let config = Config::default();
        // A simple JWT
        let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = perform_cracking(input, config);

        assert!(result.is_some(), "Should decode JWT");
        let decoded = result.unwrap();
        let text = &decoded.text[0];
        
        // Check contents
        assert!(text.contains("John Doe"), "Result should contain payload content");
        assert!(text.contains("HS256"), "Result should contain header content");
    }
}
