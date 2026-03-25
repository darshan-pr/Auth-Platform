// State
let currentPage = 'dashboard';
let apps = [];
let users = [];
let userAddMode = 'single';
let editingAppId = null;
let editingUserId = null;
let deleteCallback = null;
let selectedAppFilter = '';
let selectedUserIds = new Set();
let adminSessions = [];
let adminHistory = [];
let parsedCsvUsers = [];
let csvUploadBtnResetTimer = null;
let csvUploadState = {
    running: false,
    total: 0,
    processed: 0,
    added: 0,
    failed: 0
};
let _autoRefreshTimer = null;
let adminSettingsProfile = null;
let adminSettingsSecurity = null;
let adminSettingsPendingMfaAction = 'enable';
