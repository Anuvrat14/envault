// Auto-uppercase env variable key inputs
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('input.text-uppercase').forEach(input => {
        input.addEventListener('input', function () {
            const pos = this.selectionStart;
            this.value = this.value.toUpperCase();
            this.setSelectionRange(pos, pos);
        });
    });
});
