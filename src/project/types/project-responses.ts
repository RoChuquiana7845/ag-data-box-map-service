export interface ProjectResponse {
  success: boolean;
  data: {
    id: string;
    name: string;
    description: string;
    userId: string;
    date: Date;
  };
}

export interface ProjectListResponse {
  success: boolean;
  data: Array<{
    id: string;
    name: string;
    description: string;
    userId: string;
    date: Date;
  }>;
  pagination: {
    total: number;
    page: number;
    limit: number;
  };
}

export interface SuccessResponse {
  success: boolean;
}
