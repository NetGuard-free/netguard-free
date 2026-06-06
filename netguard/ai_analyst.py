import logging
from netguard import OLLAMA_AVAILABLE, C

logger = logging.getLogger(__name__)


class AIAnalyst:
    def __init__(self, model: str = "llama3.2", cprint_func=None, db=None):
        self.model = model
        self.cprint = cprint_func or (lambda *a: None)
        self.db = db
        self.available = OLLAMA_AVAILABLE and self._check_ollama()
        if self.available:
            self.cprint("OK", f"Lokalny LLM dostepny: {model}")
        else:
            self.cprint("WARN", "Ollama niedostepne — uzywam analizy heurystycznej")

    def _check_ollama(self) -> bool:
        try:
            import ollama
            ollama.list()
            return True
        except Exception:
            logger.debug("Ollama not available, falling back to heuristic")
            return False

    def analyze(self, context: str, question: str) -> str:
        if not self.available:
            return self._heuristic_analysis(question)
        system_prompt = """Jestes NetGuard AI — lokalnym agentem bezpieczenstwa sieci domowej.
Analizujesz dane sieciowe i pomagasz wlascicielowi chronic jego siec.
Odpowiadasz po polsku, zwiezle i konkretnie.
Uzywasz technicznych terminow ale tlumaczysz je dla zwyklego uzytkownika.
Nigdy nie wysylasz danych na zewnatrz — dzialasz wylacznie lokalnie.
Kontekst sieci: """ + context
        try:
            import ollama
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ]
            )
            return response['message']['content']
        except Exception as e:
            logger.warning("LLM query failed: %s", e)
            return f"Blad LLM: {e}\n\n{self._heuristic_analysis(question)}"

    def _heuristic_analysis(self, question: str) -> str:
        q = question.lower()
        alerts = self.db.data.get("events", []) if self.db else []
        critical = [e for e in alerts if e.get("severity") == "CRITICAL"]
        high = [e for e in alerts if e.get("severity") == "HIGH"]
        if "podejrzan" in q or "niebezpiecz" in q or "zagroz" in q:
            return (f"Analiza heurystyczna:\n"
                    f"* Zagrozenia krytyczne: {len(critical)}\n"
                    f"* Zagrozenia wysokie: {len(high)}\n"
                    f"* Ostatni alert: {critical[0]['description'] if critical else 'brak'}\n"
                    f"Zalecenie: {'Sprawdz ostatnie alerty.' if critical else 'Siec wyglada bezpiecznie.'}")
        return ("Tryb heurystyczny aktywny. Zainstaluj Ollama i pobierz model:\n"
                "  curl -fsSL https://ollama.com/install.sh | sh\n"
                "  ollama pull llama3.2")
