import { Area } from '../entities/area.entity';

export interface AreaPaginationResponse {
  success: boolean;
  data: Area[];
  pagination: {
    total: number;
    page: number;
    limit: number;
  };
}
