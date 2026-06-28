<?php
session_start();
require_once '../config.php';

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: login.php");
    exit;
}

$error = '';
$success = '';

$eventId = $_GET['id'] ?? null;
if (!$eventId) {
    header("Location: dashboard.php");
    exit;
}

// Fetch current event details
$stmt = $pdo->prepare("SELECT * FROM events WHERE id = ?");
$stmt->execute([$eventId]);
$event = $stmt->fetch();

if (!$event) {
    die("Event not found.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    verify_csrf_token($csrf);
    
    $eventName = trim($_POST['name'] ?? '');
    $linkedinCaption = trim($_POST['linkedin_caption'] ?? '');

    $passcode = trim($_POST['super_admin_passcode'] ?? '');

    if ($passcode !== SUPER_ADMIN_PASSCODE) {
        $error = "Security Error: Invalid Super Admin Passcode.";
    } elseif (!$eventName) {
        $error = "Event name is required.";
    } else {
        $stmtUpdate = $pdo->prepare("UPDATE events SET name = ?, linkedin_caption = ? WHERE id = ?");
        $stmtUpdate->execute([$eventName, $linkedinCaption, $eventId]);
        
        log_audit_action($pdo, 'Edited Event', "Event ID: {$eventId}, New Name: {$eventName}");
        
        $success = "Event updated successfully.";
        // Refresh event data
        $event['name'] = $eventName;
        $event['linkedin_caption'] = $linkedinCaption;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit Event</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <div style="display: flex; align-items: center; gap: 15px;">
        <img src="https://dcwwiki.org/images/5/56/DCW_logo.png" alt="DCW Logo" style="height: 35px; background: white; padding: 2px; border-radius: 50%;">
        <span style="font-size: 18px; font-weight: bold; letter-spacing: 0.5px;">Admin Panel - Edit Event</span>
    </div>
    <div>
        <a href="dashboard.php">Dashboard</a>
        <a href="manage_users.php" style="margin-right: 15px;">Manage Users</a>
        <a href="logout.php">Logout</a>
    </div>
</div>

<div class="container" style="max-width: 600px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h2 style="margin: 0;">Edit Event</h2>
        <a href="dashboard.php" class="btn" style="background: #6c757d;">Back</a>
    </div>
    
    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>">
        <div class="form-group">
            <label>Event Name</label>
            <input type="text" name="name" required value="<?= htmlspecialchars($event['name']) ?>">
        </div>
        
        <div class="form-group">
            <label>Certificate Prefix <span style="font-size: 11px; color: #999; font-weight: normal;">(Cannot be changed after creation)</span></label>
            <input type="text" name="cert_prefix" value="<?= htmlspecialchars($event['cert_prefix'] ?? 'DCW') ?>" readonly style="background-color: #e9ecef; color: #6c757d; cursor: not-allowed; text-transform: uppercase;">
        </div>
        
        <div class="form-group">
            <label>LinkedIn Share Message (Optional)</label>
            <textarea name="linkedin_caption" rows="4" placeholder="e.g. I'm thrilled to announce I've completed the {EVENT_NAME} workshop! Check out my verified credential here: {URL} #DCW2026" style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-family: inherit; resize: vertical;"><?= htmlspecialchars($event['linkedin_caption'] ?? '') ?></textarea>
            <div style="font-size: 11px; color: #777; margin-top: 5px;">
                Use <strong>{EVENT_NAME}</strong> and <strong>{URL}</strong> as placeholders. They will be automatically replaced when the participant shares their certificate.
            </div>
        </div>
        
        <div class="form-group" style="margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 20px;">
            <label style="color: #d9534f;">Super Admin Passcode <span style="font-size: 11px; color: #999; font-weight: normal;">(Required to save changes)</span></label>
            <input type="password" name="super_admin_passcode" required placeholder="Enter passcode to authorize">
        </div>
        
        <button type="submit" class="btn" style="width: 100%; margin-bottom: 15px;">Save Changes</button>
    </form>
    
    <form method="POST" action="dashboard.php" id="deleteForm" onsubmit="return confirmDelete();">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>">
        <input type="hidden" name="delete_event_id" value="<?= htmlspecialchars($eventId) ?>">
        <input type="hidden" name="super_admin_passcode" id="delete_passcode" value="">
        <button type="submit" class="btn btn-red" style="width: 100%;">Delete Event</button>
    </form>
</div>

<script src="script.js"></script>
<script>
    function confirmDelete() {
        if (!confirm('Are you sure you want to completely delete this event? This will erase all associated participants and certificates permanently.')) {
            return false;
        }
        
        let code = prompt("Security Check: Please enter the Super Admin Passcode to authorize this deletion:");
        if (code) {
            document.getElementById('delete_passcode').value = code;
            return true;
        }
        
        alert("Deletion cancelled: Passcode is required.");
        return false;
    }
</script>
<?php if ($error): ?>
<script>
    window.flashMessage = <?= json_encode($error) ?>;
    window.flashMessageType = 'error';
</script>
<?php elseif ($success): ?>
<script>
    window.flashMessage = <?= json_encode($success) ?>;
    window.flashMessageType = 'success';
</script>
<?php endif; ?>
</body>
</html>
