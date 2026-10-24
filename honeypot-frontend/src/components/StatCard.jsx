
export default function StatCard({
  label,
  value,
  description,
  icon: Icon,
  tone = "blue",
}) {
  return (
    <article className="stat-card">
      <div className="stat-top">
        <span className="stat-label">{label}</span>
        <span className={`stat-icon tone-${tone}`}>
          <Icon size={20} />
        </span>
      </div>

      <div className="stat-value">{value}</div>
      <div className="stat-description">{description}</div>
    </article>
  );
}
