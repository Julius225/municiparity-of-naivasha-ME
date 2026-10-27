<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $safeTitle ?> · <?= $brand ?></title>
    <link rel="stylesheet" href="<?= e(($GLOBALS['basePath'] ?? '') . '/assets/app.css') ?>">
    <?php if ($user): ?><script src="<?= e(($GLOBALS['basePath'] ?? '') . '/assets/app.js') ?>" defer></script><?php endif; ?>
</head>
<body class="<?= $user ? 'app-body' : 'public-body' ?><?= !$user && $page === 'login' ? ' login-page' : '' ?>">
<?php if ($user): ?>
    <div class="app-shell">
        <aside class="sidebar">
            <a class="brand-lockup" href="<?= e(url('dashboard')) ?>">
                <span class="brand-mark" aria-hidden="true">M</span>
                <span><strong>MunicipalFlow</strong><small>Project monitoring</small></span>
            </a>
            <div class="workspace-label">WORKSPACE</div>
            <nav class="sidebar-nav" aria-label="Main navigation"><?= $navigation ?></nav>
            <div class="sidebar-bottom">
                <div class="institution-card"><span class="institution-dot"></span><span><?= $brand ?></span></div>
                <?= $profile ?>
            </div>
        </aside>
        <div class="app-main">
            <?= $topbar ?>
            <main class="container">
                <div class="page-heading"><div><p class="eyebrow">MUNICIPAL PROJECT MONITORING &amp; EVALUATION</p><h1><?= $safeTitle ?></h1></div></div>
                <?= $flash ?>
                <?= $content ?>
            </main>
            <footer>MunicipalFlow <span aria-hidden="true">·</span> Project Monitoring &amp; Evaluation</footer>
        </div>
    </div>
<?php else: ?>
    <header class="public-header">
        <a class="brand-lockup" href="<?= e(url('login')) ?>"><span class="brand-mark" aria-hidden="true">M</span><span><strong><?= $brand ?></strong><small>Project monitoring</small></span></a>
    </header>
    <main class="public-container">
        <h1><?= $safeTitle ?></h1>
        <?= $flash ?>
        <?= $content ?>
    </main>
    <footer><?= $brand ?></footer>
<?php endif; ?>
</body>
</html>
