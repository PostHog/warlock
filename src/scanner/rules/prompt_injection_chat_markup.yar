// Catches chat-markup turn tokens (ChatML <|im_start|>, Llama [INST] /
// <<SYS>>, Claude-style "\n\nHuman:", Alpaca ### Instruction:) smuggled
// into user content. If the app glues untrusted content into a prompt
// template without screening it first, these fake a privileged turn.
//
// "Human:" requires a leading blank line so casual prose doesn't trip it.

rule prompt_injection_chat_markup
{
    meta:
        description = "Chat-markup turn tokens (ChatML, Llama 2, Claude-style, Alpaca-style) embedded in content. These can fake a privileged system or assistant turn."
        remediation = "Refuse to process the content, or strip the turn markers before passing it to a model. Don't glue untrusted content into a prompt template without cleaning these markers out first."
        severity = "critical"
        category = "prompt_injection"
        action = "block"
        scan_context = "input"

    strings:
        // ChatML (OpenAI/Qwen/others)
        $chatml_im_start = "<|im_start|>"
        $chatml_im_end = "<|im_end|>"
        $chatml_system = "<|system|>"
        $chatml_user = "<|user|>"
        $chatml_assistant = "<|assistant|>"

        // Llama 2 / Mistral INST markers
        $llama_inst_open = "[INST]"
        $llama_inst_close = "[/INST]"
        $llama_sys_open = "<<SYS>>"
        $llama_sys_close = "<</SYS>>"

        // Claude-style turn markers (leading newline required to avoid
        // matching casual "Human:" in prose / dialogue in docs)
        $claude_human = /\n\s*\n\s*Human\s*:\s/
        $claude_assistant = /\n\s*\n\s*Assistant\s*:\s/

        // Alpaca / instruction-tuned dataset headers
        $alpaca_instruction = /###\s+Instruction\s*:/
        $alpaca_response = /###\s+Response\s*:/
        $alpaca_input = /###\s+Input\s*:/

        // Qwen-style special tokens
        $qwen_endoftext = "<|endoftext|>"

    condition:
        any of them
}
