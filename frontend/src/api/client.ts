import {
  AnalyzeResponse,
  HealthResponse,
  SimulateRequest,
  SimulateResponse,
  ApiErrorDetail,
  FastApiValidationError,
} from '../types/api';

const API_BASE = ''; // Uses Vite proxy in development, or can be set to http://127.0.0.1:8000

export class ApiError extends Error {
  status: number;
  errorType?: string;
  isAnalysisExpired: boolean;
  isUnsupportedLockfile: boolean;
  isSimulationError: boolean;

  constructor(status: number, message: string, errorType?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errorType = errorType;
    this.isAnalysisExpired = status === 404 || errorType === 'AnalysisNotFoundError';
    this.isUnsupportedLockfile = errorType === 'UnsupportedLockfileVersionError';
    this.isSimulationError = errorType === 'InvalidSimulationNodeError';
  }
}

async function parseErrorResponse(response: Response): Promise<ApiError> {
  let message = `Request failed with status ${response.status} (${response.statusText})`;
  let errorType: string | undefined = undefined;

  try {
    const data = await response.json();
    if (data && data.detail) {
      if (typeof data.detail === 'string') {
        message = data.detail;
      } else if (Array.isArray(data.detail)) {
        // FastAPI validation errors
        const issues = (data.detail as FastApiValidationError[]).map(
          (item) => `${item.loc.join('.')}: ${item.msg}`
        );
        message = issues.join('; ');
      } else if (typeof data.detail === 'object') {
        const detail = data.detail as ApiErrorDetail;
        errorType = detail.error_type;
        message = detail.message || message;
      }
    }
  } catch {
    // Non-JSON response, fallback to default message
  }

  // Friendly error mapping
  if (response.status === 404 && (errorType === 'AnalysisNotFoundError' || !errorType)) {
    message = 'Analysis session expired or not found. Please re-analyze the package manifest.';
  } else if (errorType === 'UnsupportedLockfileVersionError') {
    message = 'Unsupported lockfileVersion. RippleGuard requires package-lock.json with lockfileVersion 2 or 3 (npm 7+).';
  } else if (errorType === 'ManifestParseError') {
    message = `Invalid package.json manifest: ${message}`;
  } else if (errorType === 'LockfileParseError') {
    message = `Invalid package-lock.json: ${message}`;
  } else if (errorType === 'InvalidSimulationNodeError') {
    message = `Cannot simulate node: ${message}`;
  }

  return new ApiError(response.status, message, errorType);
}

export const apiClient = {
  async checkHealth(): Promise<HealthResponse> {
    try {
      const response = await fetch(`${API_BASE}/api/health`);
      if (!response.ok) {
        throw await parseErrorResponse(response);
      }
      return await response.json();
    } catch (err: unknown) {
      if (err instanceof ApiError) throw err;
      throw new ApiError(0, 'Backend is offline or unreachable. Run "uvicorn app.main:app --reload" on port 8000.');
    }
  },

  async analyze(packageJson: File | Blob, packageLockJson?: File | Blob | null): Promise<AnalyzeResponse> {
    const formData = new FormData();
    formData.append('package_json', packageJson, (packageJson as File).name || 'package.json');

    if (packageLockJson) {
      formData.append('package_lock_json', packageLockJson, (packageLockJson as File).name || 'package-lock.json');
    }

    let response: Response;
    try {
      response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        body: formData,
      });
    } catch (err: unknown) {
      if (err instanceof ApiError) throw err;
      throw new ApiError(0, 'Backend is unreachable. Please verify the RippleGuard backend server is running.');
    }

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    return await response.json();
  },

  async simulate(analysisId: string, nodeId: string): Promise<SimulateResponse> {
    const payload: SimulateRequest = {
      analysis_id: analysisId,
      node_id: nodeId,
    };

    let response: Response;
    try {
      response = await fetch(`${API_BASE}/api/simulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
    } catch (err: unknown) {
      if (err instanceof ApiError) throw err;
      throw new ApiError(0, 'Backend is unreachable during compromise simulation.');
    }

    if (!response.ok) {
      throw await parseErrorResponse(response);
    }

    return await response.json();
  },
};
