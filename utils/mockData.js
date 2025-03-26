'use strict';

const {
    hash,
    encrypt
} = require('./cypher.js');

// Generate mock data for testing purposes
const generateMockData = () => {
    // Mock users
    const users = [
        {
            _id: '507f1f77bcf86cd799439011',
            uuid: encrypt('user-uuid-1'),
            email: encrypt('user1@example.com'),
            password: encrypt(hash('password-hash-1')),
            created_date: '2023-01-01T00:00:00.000Z',
            last_update_date: '2023-04-15T10:30:00.000Z',
            last_login_date: '2023-04-20T08:15:00.000Z',
            token: encrypt('mock-token-1'),
            totp_secret: encrypt('JBSWY3DPEHPK3PXP'),
            public_encryption_key: encrypt('mock-public-key-1'),
            avatarUrl: encrypt('https://example.com/avatar1.jpg'),
            isMFAEnabled: false,
            hasAccounts: true
        },
        {
            _id: '507f1f77bcf86cd799439022',
            uuid: encrypt('user-uuid-2'),
            email: encrypt('user2@example.com'),
            password: encrypt(hash('password-hash-2')),
            created_date: '2023-02-05T00:00:00.000Z',
            last_update_date: '2023-05-10T14:45:00.000Z',
            last_login_date: '2023-05-12T09:20:00.000Z',
            token: encrypt('mock-token-2'),
            totp_secret: encrypt('KRSXG5CTMVRXEZLU'),
            public_encryption_key: encrypt('mock-public-key-1'),
            avatarUrl: encrypt('https://example.com/avatar2.jpg'),
            isMFAEnabled: true,
            hasAccounts: true,
            passkeys: [
                {
                    passkey: {
                        id: 'passkey-id-1',
                        name: 'My Device'
                    }
                }
            ]
        }
    ];

    // Mock accounts
    const accounts = [
        {
            _id: '67e3c7608cd27ab693f0',
            user_id: encrypt('user-uuid-1'),
            created_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            last_modified_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            last_opened_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            'icon': encrypt("{\"iv\":\"ZC+NaH1Jpq3Kf9mK+wCgCg==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"HkOWayDfa60idFg6fARSPFMeqU1nKwBjB/dyi37FuIPh6fo44fMdgz6m2D23nV4IS+033DdZbRzD8bTd+wMUVnVXQ5in8zcv9rVavWL0Z6n1FPgKh38rPdfEVk6Q5dPpk/EUZV8IkbwrCIIzcVzEaApK2LYcSqZAwk8v6uWn9/3xgLEu2yO0Z/RFwApH0DpOMVP92OcF4q8etoRch2sAGZ/OWCKjzQ==\"}"),
            'platform': encrypt("{\"iv\":\"lzHvOGYyvy9PKF1lTL0b6w==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"06TqJgZ1geknSSAOzuREs7T+\"}"),
            'login': encrypt("{\"iv\":\"ntnCce0OJJzdlGcZTrtDDg==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"Kca52CZBrxSkf8bDbhF+7bMyO1aMjMA=\"}"),
            'password': '',
            'password_clue': encrypt("{\"iv\":\"eSleDp4KrcB+61Lag61Gew==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"j0SIjEB3NSzdY3UpRhXRCJo=\"}"),
            'tags': encrypt("{\"iv\":\"c+IaIDyGpQLP3iJhFMEnGw==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"3e+w8lWKV62p0TXHPGTPxDlW\"}"),
            'social_login': '',
            'description': '',
            'notes': encrypt("{\"iv\":\"Qdf+0sIftNSess/yCnA1Lw==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"nxif31gz/V9kO3+7a5m+xrrM7sPxv/alqQ==\"}"),
            'opened_count':5,
            'type':"account",
            'card_number': '',
            'card_name': '',
            'card_expiracy': '',
            'card_cryptogram': '',
            'card_pin': '',
            'totp_secret': '',
            'isServerEncrypted':true,
            'is_password_less':false
         },
        
         {
            _id: '67e3c7608cd27ab693f01',
            user_id: encrypt('user-uuid-2'),
            created_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            last_modified_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            last_opened_date: 'Wed, 26 Mar 2025 09:21:29 GMT',
            'icon': encrypt("{\"iv\":\"ZC+NaH1Jpq3Kf9mK+wCgCg==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"HkOWayDfa60idFg6fARSPFMeqU1nKwBjB/dyi37FuIPh6fo44fMdgz6m2D23nV4IS+033DdZbRzD8bTd+wMUVnVXQ5in8zcv9rVavWL0Z6n1FPgKh38rPdfEVk6Q5dPpk/EUZV8IkbwrCIIzcVzEaApK2LYcSqZAwk8v6uWn9/3xgLEu2yO0Z/RFwApH0DpOMVP92OcF4q8etoRch2sAGZ/OWCKjzQ==\"}"),
            'platform': encrypt("{\"iv\":\"lzHvOGYyvy9PKF1lTL0b6w==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"06TqJgZ1geknSSAOzuREs7T+\"}"),
            'login': encrypt("{\"iv\":\"ntnCce0OJJzdlGcZTrtDDg==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"Kca52CZBrxSkf8bDbhF+7bMyO1aMjMA=\"}"),
            'password': '',
            'password_clue': encrypt("{\"iv\":\"eSleDp4KrcB+61Lag61Gew==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"j0SIjEB3NSzdY3UpRhXRCJo=\"}"),
            'tags': encrypt("{\"iv\":\"c+IaIDyGpQLP3iJhFMEnGw==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"3e+w8lWKV62p0TXHPGTPxDlW\"}"),
            'social_login': '',
            'description': '',
            'notes': encrypt("{\"iv\":\"Qdf+0sIftNSess/yCnA1Lw==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"Txb6PApncjQ=\",\"ct\":\"nxif31gz/V9kO3+7a5m+xrrM7sPxv/alqQ==\"}"),
            'opened_count':5,
            'type':"account",
            'card_number': '',
            'card_name': '',
            'card_expiracy': '',
            'card_cryptogram': '',
            'card_pin': '',
            'totp_secret': '',
            'isServerEncrypted':true,
            'is_password_less':false
         }
    ];

    // Mock user activities
    const activities = [
        {
            _id: '507f1f77bcf86cd799439066',
            uuid: encrypt('user-uuid-1'),
            action: encrypt('login'),
            agent: encrypt('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/93.0.4577.82'),
            referer: encrypt('https://app.example.com'),
            ip: encrypt('192.168.1.100'),
            activity_date: '2023-04-15T10:30:00.000Z',
            location: encrypt('San Francisco, USA')
        },
        {
            _id: '507f1f77bcf86cd799439077',
            uuid: encrypt('user-uuid-1'),
            action: encrypt('account_update'),
            agent: encrypt('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/93.0.4577.82'),
            referer: encrypt('https://app.example.com'),
            ip: encrypt('192.168.1.100'),
            activity_date: '2023-04-16T14:15:00.000Z',
            location: encrypt('San Francisco, USA')
        },
        {
            _id: '507f1f77bcf86cd799439088',
            uuid: encrypt('user-uuid-2'),
            action: encrypt('login'),
            agent: encrypt('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15'),
            referer: encrypt('https://app.example.com'),
            ip: encrypt('10.0.0.5'),
            activity_date: '2023-05-10T14:45:00.000Z',
            location: encrypt('New York, USA')
        }
    ];

    return {
        users,
        accounts,
        activities
    };
};

module.exports = generateMockData; 