const REPOSITORY_FACT_PATHS = new Map([
  ['durable-workflow.com', '/repos/durable-workflow/workflow'],
  ['php.durable-workflow.com', '/repos/durable-workflow/sdk-php'],
  ['python.durable-workflow.com', '/repos/durable-workflow/sdk-python'],
  ['rust.durable-workflow.com', '/repos/durable-workflow/sdk-rust'],
]);

export function allowedRepositoryFactsOrigin(captureUrl, requestUrl) {
  return REPOSITORY_FACT_PATHS.has(captureUrl.hostname)
    && requestUrl.origin === 'https://api.github.com';
}

export function allowedRepositoryFactsRequest(captureUrl, requestUrl, method, resourceType) {
  const repositoryPath = REPOSITORY_FACT_PATHS.get(captureUrl.hostname);
  return Boolean(repositoryPath)
    && requestUrl.origin === 'https://api.github.com'
    && requestUrl.pathname === repositoryPath
    && requestUrl.search === ''
    && method === 'GET'
    && ['fetch', 'xhr'].includes(resourceType);
}
