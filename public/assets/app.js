document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.sidebar-toggle');
    if (toggle) {
        toggle.addEventListener('click', () => {
            const isCollapsed = document.body.classList.toggle('sidebar-collapsed');
            toggle.setAttribute('aria-expanded', String(!isCollapsed));
            toggle.setAttribute('aria-label', isCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
        });
    }

    const projectTabs = document.querySelectorAll('.project-tabs a');
    const updateProjectTab = () => {
        const target = window.location.hash || '#overview';
        projectTabs.forEach((tab) => {
            const active = tab.getAttribute('href') === target;
            tab.classList.toggle('active', active);
            if (active) {
                tab.setAttribute('aria-current', 'location');
            } else {
                tab.removeAttribute('aria-current');
            }
        });
    };
    if (projectTabs.length > 0) {
        projectTabs.forEach((tab) => tab.addEventListener('click', updateProjectTab));
        window.addEventListener('hashchange', updateProjectTab);
        updateProjectTab();
    }

    document.querySelectorAll('input[type="file"][name="project_media"], input[type="file"][name="document"]').forEach((input) => {
        const preview = input.closest('form')?.querySelector('[data-media-preview]');
        if (!preview) return;

        input.addEventListener('change', () => {
            if (preview.dataset.objectUrl) {
                URL.revokeObjectURL(preview.dataset.objectUrl);
                delete preview.dataset.objectUrl;
            }
            preview.replaceChildren();

            const file = input.files?.[0];
            if (!file) {
                preview.hidden = true;
                return;
            }

            const fileName = document.createElement('p');
            fileName.className = 'media-preview-name';
            fileName.textContent = file.name;
            preview.append(fileName);

            if (file.type.startsWith('image/')) {
                const image = document.createElement('img');
                image.src = URL.createObjectURL(file);
                image.alt = `Preview of ${file.name}`;
                preview.dataset.objectUrl = image.src;
                preview.append(image);
            } else if (file.type.startsWith('video/')) {
                const video = document.createElement('video');
                video.src = URL.createObjectURL(file);
                video.controls = true;
                video.preload = 'metadata';
                preview.dataset.objectUrl = video.src;
                preview.append(video);
            }

            preview.hidden = false;
        });
    });

    let evidenceDialog;
    document.addEventListener('click', (event) => {
        const link = event.target.closest('a[data-evidence-image]');
        if (!link || typeof HTMLDialogElement === 'undefined') return;

        event.preventDefault();
        if (!evidenceDialog) {
            evidenceDialog = document.createElement('dialog');
            evidenceDialog.className = 'evidence-dialog';
            evidenceDialog.setAttribute('aria-label', 'Evidence photo');

            const closeButton = document.createElement('button');
            closeButton.className = 'evidence-dialog-close';
            closeButton.type = 'button';
            closeButton.setAttribute('aria-label', 'Close photo');
            closeButton.textContent = '×';
            closeButton.addEventListener('click', () => evidenceDialog.close());

            const image = document.createElement('img');
            image.className = 'evidence-dialog-image';
            evidenceDialog.append(closeButton, image);
            evidenceDialog.addEventListener('click', (dialogEvent) => {
                if (dialogEvent.target === evidenceDialog) evidenceDialog.close();
            });
            evidenceDialog.addEventListener('close', () => {
                evidenceDialog.querySelector('img').removeAttribute('src');
            });
            document.body.append(evidenceDialog);
        }

        const image = evidenceDialog.querySelector('img');
        image.src = link.href;
        image.alt = link.textContent.trim();
        evidenceDialog.showModal();
    });
});
