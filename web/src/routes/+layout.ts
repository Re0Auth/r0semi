// The app is a pure client-side single-page app.
//
// adapter-static emits one shell and this disables server rendering for every
// route. Two reasons, and only the first is about convenience:
//
//   1. Every page here is empty until /v1 answers, and /v1 wants the browser's
//      own session cookie. Rendering on a server would mean forwarding that
//      cookie, which means putting a second copy of the session on the path.
//
//   2. More importantly, it keeps one rule true: the answer to "what does this
//      consent screen say" is assembled in exactly one place, from one fetch.
//      Anything the server rendered would be a second assembly, and the two
//      would eventually disagree — on the screen whose entire job is to be
//      trusted about what is being granted.
export const ssr = false;
