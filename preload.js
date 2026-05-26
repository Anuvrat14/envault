window.addEventListener('DOMContentLoaded', () => {
    if (process.platform !== 'win32') return;

    const style = document.createElement('style');
    style.textContent = `
        .navbar { -webkit-app-region: drag; }
        .navbar .container-fluid { justify-content: flex-start !important; gap: 24px; }
        .navbar a, .navbar button, .navbar input,
        .navbar select, .navbar label { -webkit-app-region: no-drag; }
    `;
    document.head.appendChild(style);
});
