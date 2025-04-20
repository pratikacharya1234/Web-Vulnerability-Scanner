module.exports = {
    scan: async (page, url) => {
      const idorIndicators = ['user_id=', 'account=', 'profile_id='];
      const found = idorIndicators.filter(ind => page.url.includes(ind));
      if (found.length) {
        return [{
          type: 'Insecure Direct Object Reference (IDOR)',
          severity: 'medium',
          url,
          description: 'URL contains sensitive identifiers that may be manipulated.',
          recommendation: 'Implement access control for user data objects.',
          evidence: found.join(', ')
        }];
      }
      return [];
    }
  };
  