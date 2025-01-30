import { Test, TestingModule } from '@nestjs/testing';
import { SampleGridService } from './sample-grid.service';

describe('SampleGridService', () => {
  let service: SampleGridService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SampleGridService],
    }).compile();

    service = module.get<SampleGridService>(SampleGridService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
