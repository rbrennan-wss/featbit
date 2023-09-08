export const environment = {
  production: false,
  enableSchedule: false,
  url: window['env']['apiUrl'] || 'https://api.featbit.example',
  demoUrl: window['env']['demoUrl'] || 'https://featbit-samples.vercel.app',
  evaluationUrl: window['env']['evaluationUrl'] || 'http://eval.featbit.example',
};
