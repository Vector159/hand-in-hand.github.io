// Chatbot simple para Hand in Hand
class SimpleHandInHandChatbot {
  constructor() {
    this.responses = {
      // Preguntas sobre la plataforma
      "qué es hand in hand":
        "Hand in Hand es una plataforma que conecta productores locales con consumidores conscientes, facilitando el comercio directo de productos frescos y artesanales.",
      "cómo funciona":
        "Nuestra plataforma permite a los productores locales registrarse y ofrecer sus productos. Los consumidores pueden explorar, contactar directamente y comprar productos de estos productores.",
      "quiénes son":
        "Somos un equipo comprometido con la agricultura sostenible y el comercio justo. Nuestra misión es acortar la cadena de suministro entre productores y consumidores.",

      // Preguntas sobre productores
      "cómo registrarse como productor":
        "Para registrarte como productor, haz clic en 'Registrarse' en la parte superior de la página, completa el formulario y selecciona la opción 'Soy productor'. Luego verifica tu correo electrónico y completa tu perfil.",
      "qué productos puedo vender":
        "Puedes vender productos agrícolas frescos, alimentos artesanales, productos orgánicos, y cualquier producto local que cumpla con nuestras directrices de calidad y sostenibilidad.",
      "cómo publicar productos":
        "Una vez registrado como productor, ve a tu perfil, haz clic en 'Añadir producto' y completa la información requerida incluyendo descripción, precio, disponibilidad y fotos.",

      // Preguntas sobre consumidores
      "cómo comprar":
        "Para comprar, explora los productos disponibles, selecciona los que te interesen y contacta directamente con el productor a través de nuestra plataforma para acordar la entrega y el pago.",
      "métodos de pago":
        "Los métodos de pago varían según el productor. Generalmente se acepta efectivo, transferencias bancarias y algunos productores pueden ofrecer pagos con tarjeta o digitales.",
      entregas:
        "Las opciones de entrega son acordadas directamente entre el productor y el consumidor. Pueden incluir recogida en el lugar de producción, puntos de encuentro o entregas a domicilio.",

      // Preguntas sobre la cuenta
      "olvidé mi contraseña":
        "Si olvidaste tu contraseña, haz clic en 'Iniciar Sesión', luego en '¿Olvidaste tu contraseña?' y sigue las instrucciones enviadas a tu correo electrónico.",
      "cambiar datos":
        "Para cambiar tus datos personales, inicia sesión, ve a tu perfil y haz clic en 'Editar perfil'. Allí podrás actualizar tu información.",
      "eliminar cuenta":
        "Para eliminar tu cuenta, ve a tu perfil, haz clic en 'Configuración' y selecciona 'Eliminar cuenta'. Confirma la acción siguiendo las instrucciones.",

      // Respuestas por defecto
      default:
        "Lo siento, no tengo información sobre eso. ¿Puedes reformular tu pregunta o preguntar sobre otro tema relacionado con Hand in Hand?",
      greeting: "¡Hola! Soy el asistente virtual de Hand in Hand. ¿En qué puedo ayudarte hoy?",
      thanks: "¡De nada! Estoy aquí para ayudarte. Si tienes más preguntas, no dudes en consultarme.",
      goodbye: "¡Gracias por contactar con Hand in Hand! Si necesitas más ayuda, estaré aquí. ¡Que tengas un buen día!",
    }

    // Palabras clave para identificar saludos, agradecimientos y despedidas
    this.greetings = ["hola", "buenos días", "buenas tardes", "buenas noches", "saludos"]
    this.thanks = ["gracias", "te lo agradezco", "muchas gracias"]
    this.goodbyes = ["adiós", "hasta luego", "chao", "nos vemos"]
  }

  // Método para procesar la entrada del usuario y devolver una respuesta
  processInput(userInput) {
    if (!userInput) return this.responses["greeting"]

    // Convertir a minúsculas para facilitar la comparación
    const input = userInput.toLowerCase()

    // Verificar si es un saludo, agradecimiento o despedida
    if (this.greetings.some((greeting) => input.includes(greeting))) {
      return this.responses["greeting"]
    }

    if (this.thanks.some((thank) => input.includes(thank))) {
      return this.responses["thanks"]
    }

    if (this.goodbyes.some((goodbye) => input.includes(goodbye))) {
      return this.responses["goodbye"]
    }

    // Buscar una respuesta específica
    for (const [key, value] of Object.entries(this.responses)) {
      if (input.includes(key)) {
        return value
      }
    }

    // Si no se encuentra una respuesta específica, devolver la respuesta por defecto
    return this.responses["default"]
  }
}

// Exportar la clase para su uso
if (typeof module !== "undefined" && module.exports) {
  module.exports = SimpleHandInHandChatbot
}
