export function formatPhoneNumber(phoneNumber: string) {
  if(!phoneNumber) return "";
  const lastTwoDigits = phoneNumber.slice(-2);
  const asterisks = '*'.repeat(phoneNumber.length - 2);
  return `${asterisks}${lastTwoDigits}`;
}

export function formatEmail(email: string) {
  if (!email) return "";
  const [username, domain] = email.split("@");
  const visibleUsername = username.charAt(0) + "*".repeat(username.length - 2) + username.charAt(username.length - 1);
  return `${visibleUsername}@${domain}`;
}