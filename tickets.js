import { getAuth } from '../auth.js';
import { showNotification, toggleButtonLoading } from '../ui.js';

const API = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export function openTicketModal() {
  const dialog = document.getElementById('ticketDialog');
  if (dialog) dialog.showModal();
}

export function setupTicketForm() {
  const form = document.getElementById('ticketForm');
  const dialog = document.getElementById('ticketDialog');

  if (!form) return;

  form.onsubmit = async (e) => {
    e.preventDefault();
    const submitBtn = form.querySelector('button[type="submit"]');
    toggleButtonLoading(submitButton, true);

    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    const auth = getAuth();

    if (!auth || !auth.token) {
      toggleButtonLoading(submitButton, false);
      showNotification('You must be logged in.', 'error');
      return;
    }

    try {
      const res = await fetch(`${API}/api/tickets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${auth.token}`
        },
        body: JSON.stringify(data)
      });
      const json = await res.json();
      if (res.ok) {
        showNotification(`Ticket created! ID: ${json.ticket.id}`, 'success');
        form.reset();
        if (dialog) dialog.close();
      } else {
        showNotification(`Error: ${json.error}`, 'error');
      }
    } catch (err) {
      console.error(err);
      showNotification('Network error', 'error');
    } finally {
      toggleButtonLoading(submitButton, false);
    }
  };
  
  // Close dialog when clicking outside
  if (dialog) {
    dialog.addEventListener('click', (e) => {
      if (e.target === dialog) dialog.close();
    });
  }
}