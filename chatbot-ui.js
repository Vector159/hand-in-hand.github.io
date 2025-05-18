document.addEventListener("DOMContentLoaded", () => {
  // Crear instancia del chatbot
  // Assuming SimpleHandInHandChatbot is defined elsewhere or imported
  // For demonstration, let's create a simple mock:
  class SimpleHandInHandChatbot {
    processInput(input) {
      if (input === "") {
        return "¡Hola! ¿En qué puedo ayudarte?"
      } else if (input.toLowerCase().includes("hola")) {
        return "¡Hola! ¿Cómo estás?"
      } else {
        return "Lo siento, no entiendo tu pregunta."
      }
    }
  }
  const chatbot = new SimpleHandInHandChatbot()

  // Elementos del DOM
  const chatbotContainer = document.createElement("div")
  chatbotContainer.className = "chatbot-container"

  // Botón para abrir/cerrar el chatbot
  const chatbotButton = document.createElement("button")
  chatbotButton.className = "chatbot-button"
  chatbotButton.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
        </svg>
    `

  // Panel del chatbot
  const chatbotPanel = document.createElement("div")
  chatbotPanel.className = "chatbot-panel"
  chatbotPanel.style.display = "none"

  // Cabecera del chatbot
  const chatbotHeader = document.createElement("div")
  chatbotHeader.className = "chatbot-header"
  chatbotHeader.innerHTML = `
        <div class="chatbot-title">
            <img src="https://cdn-icons-png.flaticon.com/512/4712/4712010.png" alt="Chatbot" class="chatbot-avatar">
            <span>Asistente Hand in Hand</span>
        </div>
        <button class="chatbot-close">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        </button>
    `

  // Área de mensajes
  const chatbotMessages = document.createElement("div")
  chatbotMessages.className = "chatbot-messages"

  // Área de entrada
  const chatbotInput = document.createElement("div")
  chatbotInput.className = "chatbot-input"
  chatbotInput.innerHTML = `
        <input type="text" placeholder="Escribe tu pregunta aquí...">
        <button class="chatbot-send">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
        </button>
    `

  // Construir la estructura del chatbot
  chatbotPanel.appendChild(chatbotHeader)
  chatbotPanel.appendChild(chatbotMessages)
  chatbotPanel.appendChild(chatbotInput)

  chatbotContainer.appendChild(chatbotButton)
  chatbotContainer.appendChild(chatbotPanel)

  // Añadir el chatbot al body
  document.body.appendChild(chatbotContainer)

  // Funcionalidad para abrir/cerrar el chatbot
  chatbotButton.addEventListener("click", () => {
    if (chatbotPanel.style.display === "none") {
      chatbotPanel.style.display = "flex"
      // Si es la primera vez que se abre, mostrar mensaje de bienvenida
      if (chatbotMessages.children.length === 0) {
        addMessage("bot", chatbot.processInput(""))
      }
    } else {
      chatbotPanel.style.display = "none"
    }
  })

  // Cerrar el chatbot
  chatbotHeader.querySelector(".chatbot-close").addEventListener("click", () => {
    chatbotPanel.style.display = "none"
  })

  // Enviar mensaje
  const sendMessage = () => {
    const inputElement = chatbotInput.querySelector("input")
    const userMessage = inputElement.value.trim()

    if (userMessage) {
      // Añadir mensaje del usuario
      addMessage("user", userMessage)

      // Limpiar input
      inputElement.value = ""

      // Simular tiempo de respuesta (opcional)
      setTimeout(() => {
        // Procesar la entrada y obtener respuesta
        const botResponse = chatbot.processInput(userMessage)

        // Añadir respuesta del bot
        addMessage("bot", botResponse)

        // Scroll al último mensaje
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight
      }, 500)
    }
  }

  // Enviar mensaje al hacer clic en el botón
  chatbotInput.querySelector(".chatbot-send").addEventListener("click", sendMessage)

  // Enviar mensaje al presionar Enter
  chatbotInput.querySelector("input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      sendMessage()
    }
  })

  // Función para añadir mensajes al chat
  function addMessage(sender, text) {
    const messageElement = document.createElement("div")
    messageElement.className = `chatbot-message ${sender}-message`

    // Si es un mensaje del bot, añadir avatar
    if (sender === "bot") {
      messageElement.innerHTML = `
                <div class="message-avatar">
                    <img src="https://cdn-icons-png.flaticon.com/512/4712/4712010.png" alt="Bot">
                </div>
                <div class="message-content">${text}</div>
            `
    } else {
      messageElement.innerHTML = `<div class="message-content">${text}</div>`
    }

    chatbotMessages.appendChild(messageElement)

    // Scroll al último mensaje
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight
  }

  // Añadir estilos CSS
  const style = document.createElement("style")
  style.textContent = `
        .chatbot-container {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            font-family: Arial, sans-serif;
        }
        
        .chatbot-button {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
        }
        
        .chatbot-button:hover {
            background-color: #45a049;
            transform: scale(1.05);
        }
        
        .chatbot-panel {
            position: absolute;
            bottom: 70px;
            right: 0;
            width: 350px;
            height: 500px;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .chatbot-header {
            padding: 15px;
            background-color: #4CAF50;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chatbot-title {
            display: flex;
            align-items: center;
        }
        
        .chatbot-avatar {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            margin-right: 10px;
            background-color: white;
        }
        
        .chatbot-close {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
        }
        
        .chatbot-messages {
            flex: 1;
            padding: 15px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        
        .chatbot-message {
            margin-bottom: 15px;
            max-width: 80%;
            display: flex;
        }
        
        .bot-message {
            align-self: flex-start;
        }
        
        .user-message {
            align-self: flex-end;
        }
        
        .message-avatar {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            margin-right: 10px;
            overflow: hidden;
        }
        
        .message-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .message-content {
            padding: 10px 15px;
            border-radius: 18px;
            background-color: #f1f1f1;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .bot-message .message-content {
            background-color: #f1f1f1;
            color: #333;
        }
        
        .user-message .message-content {
            background-color: #4CAF50;
            color: white;
        }
        
        .chatbot-input {
            padding: 15px;
            border-top: 1px solid #e0e0e0;
            display: flex;
        }
        
        .chatbot-input input {
            flex: 1;
            padding: 10px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 20px;
            outline: none;
        }
        
        .chatbot-send {
            background: none;
            border: none;
            color: #4CAF50;
            cursor: pointer;
            margin-left: 10px;
        }
        
        /* Estilos para dispositivos móviles */
        @media (max-width: 480px) {
            .chatbot-panel {
                width: 100%;
                height: 100%;
                bottom: 0;
                right: 0;
                border-radius: 0;
            }
        }
    `

  document.head.appendChild(style)
})
